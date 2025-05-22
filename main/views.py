from django.shortcuts import render
from django.db import models
# Create your views here.
from django.core.serializers.json import DjangoJSONEncoder
from .models import ExternalDatabase, Message, Parameter, ImportedColumn, ImportedTable, SubCategory, Category, Query, QueryGroup, QueryCondition, QueryLog
from django.contrib.auth.decorators import login_required
from .utils.introspect_db import introspect_database
from django.shortcuts import get_object_or_404
# views.py
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.utils.dateparse import parse_date
from django.contrib.auth.models import User
from .forms import UserRegistrationForm
from django.contrib.auth import logout
from collections import defaultdict
from django.contrib import messages
from django.views.decorators.http import require_http_methods, require_GET
import json, uuid, pymysql, hashlib

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirect to login after successful registration
    else:
        form = UserRegistrationForm()
    return render(request, 'main/register.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def column_mapping_view(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("Access denied.")
    parameters_in_use = set(
        ImportedColumn.objects.exclude(mapped_parameter__isnull=True)
        .values_list('mapped_parameter_id', flat=True)
    )
    categories = Category.objects.prefetch_related("subcategory_set__parameter_set").all()
    columns = ImportedColumn.objects.select_related("mapped_parameter", "table__external_db").all()
    param_lookup = {
        p.id: {
            "category": p.subcategory.category.name,
            "subcategory": p.subcategory.name
        }
        for p in Parameter.objects.select_related("subcategory__category")
    }
    # Group unassigned columns by DB > Table
    grouped = defaultdict(lambda: defaultdict(list))

    for col in columns:
        # if col.mapped_parameter is None:
        db = col.table.external_db.name
        table = col.table.name
        grouped[db][table].append(col)

    # ✅ Convert to plain nested dict
    grouped_unassigned = {db: dict(tables) for db, tables in grouped.items()}
    

    return render(request, "main/column_mapping.html", {
        "categories": categories,
        "columns": columns,
        "grouped_unassigned": grouped_unassigned,
        "param_lookup": param_lookup,
        "parameters_in_use": parameters_in_use,
    })

@csrf_exempt
def map_column(request):
    if request.method == "POST":
        data = json.loads(request.body)
        column_id = data.get("column_id")
        parameter_id = data.get("parameter_id")

        try:
            column = ImportedColumn.objects.get(id=column_id)
            param = Parameter.objects.get(id=parameter_id)

            # Unmap any previous column assigned to this parameter (1:1 mapping enforced)
            existing = ImportedColumn.objects.filter(mapped_parameter=param).exclude(id=column.id)
            if existing.exists():
                existing.update(mapped_parameter=None)

            # Unmap the column from any other parameter it was previously mapped to
            if column.mapped_parameter and column.mapped_parameter != param:
                column.mapped_parameter = None

            # Map the column to the new parameter
            column.mapped_parameter = param
            column.save()

            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)

@csrf_exempt
def unassign_column(request):
    if request.method == "POST":
        data = json.loads(request.body)
        column_id = data.get("column_id")

        try:
            column = ImportedColumn.objects.get(id=column_id)
            column.mapped_parameter = None
            column.save()
            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)

def serialize_categories():
    categories = []
    for cat in Category.objects.prefetch_related("subcategory_set__parameter_set").all():
        subcategories = []
        for sub in cat.subcategory_set.all():
            parameters = []
            for param in sub.parameter_set.all():
                parameters.append({
                    "id": param.id,
                    "name": param.name,
                    "data_type": param.data_type,
                    "is_phi": param.is_phi,
                    "is_hhi": param.is_hhi
                })
            subcategories.append({
                "id": sub.id,
                "name": sub.name,
                "parameters": parameters
            })
        categories.append({
            "id": cat.id,
            "name": cat.name,
            "subcategories": subcategories
        })
    return categories

@login_required
def query_builder_view(request):
    structured_categories = serialize_categories()
    return render(request, "main/query_builder.html", {
        "structured_categories": json.dumps(structured_categories, cls=DjangoJSONEncoder)
    })

# Extract used parameter IDs from query JSON
def extract_used_param_ids(group):
    ids = []
    for child in group["children"]:
        if child["type"] == "condition":
            ids.append(int(child["parameter"]))
        elif child["type"] == "group":
            ids.extend(extract_used_param_ids(child))
    return ids

def build_where_clause(group, param_map):
    sql_parts = []

    for idx, item in enumerate(group['children']):
        if item['type'] == 'condition':
            try:
                param = param_map.get(int(item['parameter']))
                if not param:
                    continue

                col = f"`{param['table']}`.`{param['column']}`"
                operator = item['operator'].lower()
                value = item.get("value", [])
                # Handle case: string from UI vs list
                if isinstance(value, str):
                    value = [v.strip() for v in value.split(",") if v.strip()]

                # Map operator to SQL
                op_map = {
                    'is_equal_to': '=',
                    'is_not_equal_to': '!=',
                    'contains': 'LIKE',
                    'does_not_contain': 'NOT LIKE',
                    'is_included': 'IN',
                    'is_excluded': 'NOT_IN',
                    'starts_with': 'LIKE',
                    'ends_with': 'LIKE',
                    'is_between': 'BETWEEN',
                    'exists': 'IS NOT NULL',
                    'does_not_exist': 'IS NULL'
                }

                if operator in ['contains', 'does_not_contain']:
                    like_conditions = [f"{col} {op_map[operator]} '%{v}%'" for v in value]
                    logic = " OR " if operator == 'contains' else " AND "
                    condition = f"({logic.join(like_conditions)})"
                elif operator == 'is_included':
                    in_values = ", ".join(f"'{v}'" for v in value)
                    condition = f"{col} IN ({in_values})"
                elif operator == 'is_excluded':
                    in_values = ", ".join(f"'{v}'" for v in value)
                    condition = f"{col} NOT IN ({in_values})"
                elif operator == 'starts_with':
                    like_conditions = [f"{col} LIKE '{v}%'" for v in value]
                    condition = "(" + " OR ".join(like_conditions) + ")"
                elif operator == 'ends_with':
                    like_conditions = [f"{col} LIKE '%{v}'" for v in value]
                    condition = "(" + " OR ".join(like_conditions) + ")"
                elif operator == 'is_equal_to':
                    if len(value) == 1:
                        condition = f"{col} = '{value[0]}'"
                    else:
                        or_conditions = [f"{col} = '{v}'" for v in value]
                        condition = "(" + " OR ".join(or_conditions) + ")"
                elif operator == 'is_not_equal_to':
                    if len(value) == 1:
                        condition = f"{col} != '{value[0]}'"
                    else:
                        and_conditions = [f"{col} != '{v}'" for v in value]
                        condition = "(" + " AND ".join(and_conditions) + ")"

                elif operator == 'is_between':
                    val0 = item.get("value0", "").strip()
                    val1 = item.get("value1", "").strip()
                    if val0 and val1:
                        condition = f"{col} BETWEEN '{val0}' AND '{val1}'"
                    else:
                        continue  # skip if either value is missing
                elif operator == 'exists':
                    condition = f"{col} IS NOT NULL" 
                elif operator == 'does_not_exist':
                    condition = f"{col} IS NULL"
                else:
                    condition = f"{col} = '{value}'"  # Fallback

                wrapped = f"({condition})"
                if idx == 0:
                    sql_parts.append(wrapped)
                else:
                    logic = item.get("logic", "AND")
                    sql_parts.append(f" {logic} {wrapped}")

            except Exception as e:
                print(f"[Error in condition] {e}")
                continue

        elif item['type'] == 'group':
            try:
                subgroup_clause = build_where_clause(item, param_map)
                if subgroup_clause:
                    wrapped = f"({subgroup_clause})"
                    if idx == 0:
                        sql_parts.append(wrapped)
                    else:
                        logic = item.get("logic", "AND")
                        sql_parts.append(f" {logic} {wrapped}")
            except Exception as e:
                print(f"[Error in group] {e}")
                continue

    return ''.join(sql_parts)

from django.http import JsonResponse
from .models import Parameter, ImportedTable, QueryLog
import pymysql
import json

@login_required
def run_query(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Only POST method is allowed."}, status=405)

    data = json.loads(request.body)

    QueryLog.objects.create(
        user=request.user,
        query_structure=data.get("query", {}),
        output_parameters=data.get("output_parameters", [])
    )

    param_map = {}
    for param in Parameter.objects.select_related("subcategory__category").all():
        try:
            imported_column = param.importedcolumn
            param_map[param.id] = {
                "column": imported_column.name,
                "table": imported_column.table.name,
                "table_type": imported_column.table.table_type,
                "db": imported_column.table.external_db.db_name
            }
        except Exception:
            continue

    used_param_ids = extract_used_param_ids(data["query"])
    selected_output_ids = set(map(int, data.get("output_parameters", [])))
    merged_output_ids = list(set(used_param_ids) | selected_output_ids)

    needs_study_info = any(param_map[int(pid)]["table_type"] == "study" for pid in merged_output_ids)
    needed_study_sub_tables = {param_map[int(pid)]["table"]
                               for pid in merged_output_ids
                               if param_map[int(pid)]["table_type"] == "study_sub"}

    joins = ["`patient_info`"]
    if needs_study_info or needed_study_sub_tables:
        joins.append("INNER JOIN `study_info` ON `study_info`.`MRN` = `patient_info`.`MRN`")

    for sub_table in needed_study_sub_tables:
        joins.append(f"LEFT JOIN `{sub_table}` ON `{sub_table}`.`Study_ID` = `study_info`.`Study_ID`")

    tables_clause = "\n".join(joins)

    # Always internally add MRN and Study_ID for unique count
    internal_id_columns = ["`patient_info`.`MRN`"]
    if needs_study_info or needed_study_sub_tables:
        internal_id_columns.append("`study_info`.`Study_ID`")

    output_columns = [f"`{param_map[int(pid)]['table']}`.`{param_map[int(pid)]['column']}`"
                      for pid in merged_output_ids if int(pid) in param_map]

    select_clause = ", ".join(set(output_columns + internal_id_columns)) if output_columns else "*"

    where_clause = build_where_clause(data["query"], param_map)

    any_param = next(iter(param_map.values()))
    external_db = ImportedTable.objects.get(name=any_param['table']).external_db

    connection = pymysql.connect(
        host=external_db.host,
        user=external_db.user,
        password=external_db.password,
        database=external_db.db_name,
        port=external_db.port
    )

    sql = f"SELECT {select_clause} FROM {tables_clause} WHERE {where_clause}"
    print(sql)

    with connection.cursor() as cursor:
        cursor.execute(sql)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()

    connection.close()

    result_dicts = [dict(zip(columns, row)) for row in rows]

    # Compute unique count using MRN or Study_ID even if not in output
    unique_ids = set()
    if "MRN" in columns:
        unique_ids = {row["MRN"] for row in result_dicts if row.get("MRN")}
    elif "Study_ID" in columns:
        unique_ids = {row["Study_ID"] for row in result_dicts if row.get("Study_ID")}

    # Prepare display results (remove internal ID columns if not requested)
    display_columns = [col for col in columns if col not in ["MRN", "Study_ID"] or
                       col in [param_map[int(pid)]["column"] for pid in merged_output_ids]]

    display_results = [
        {k: row[k] for k in display_columns} for row in result_dicts
    ]

    return JsonResponse({
        "status": "success",
        "results": display_results,
        "columns": display_columns,
        "unique_count": len(unique_ids)
    })



@csrf_exempt
def save_query_structure(request):
    if request.method == "POST":
        data = json.loads(request.body)
        user = request.user

        name = data.get("name", "Untitled Query")
        root = data["query"]

        query = Query.objects.create(name=name, created_by=user)
        root_group = QueryGroup.objects.create(query=query, logic=root["logic"])

        def save_group(group_data, parent=None, position=0):
            group = QueryGroup.objects.create(query=query, parent=parent, logic=group_data.get("logic"), position=position)
            for i, child in enumerate(group_data["children"]):
                if child["type"] == "group":
                    save_group(child, group, i)
                elif child["type"] == "condition":
                    QueryCondition.objects.create(
                        group=group,
                        parameter_id=int(child["parameter"]),
                        operator=child["operator"],
                        value=child.get("value"),
                        value0=child.get("value0", ""),
                        value1=child.get("value1", ""),
                        logic=child.get("logic", "AND"),
                        position=i
                    )

        save_group(root, root_group)
        return JsonResponse({"status": "success", "message": "Query saved successfully"})

@login_required
def list_queries(request):
    queries = Query.objects.filter(created_by=request.user).order_by('-created_at')
    return JsonResponse([{"id": q.id, "name": q.name} for q in queries], safe=False)

@login_required
def load_query(request, query_id):
    try:
        query = Query.objects.get(id=query_id, created_by=request.user)
        root_group = QueryGroup.objects.get(query=query, parent=None)

        def serialize_group(group):
            children = []

            # Sort groups/conditions by position
            subgroups = list(QueryGroup.objects.filter(parent=group).order_by("position"))
            conditions = list(QueryCondition.objects.filter(group=group).order_by("position"))

            merged = sorted(
                [(g.position, "group", g) for g in subgroups] +
                [(c.position, "condition", c) for c in conditions],
                key=lambda x: x[0]
            )

            for _, kind, obj in merged:
                if kind == "group":
                    children.append(serialize_group(obj))
                elif kind == "condition":
                    children.append({
                        "id": str(obj.id),
                        "type": "condition",
                        "parameter": obj.parameter.id,
                        "operator": obj.operator,
                        "value": obj.value,
                        "value0": obj.value0,
                        "value1": obj.value1,
                        "logic": obj.logic
                    })

            return {
                "id": str(group.id),
                "type": "group",
                "logic": group.logic,
                "children": children
            }

        return JsonResponse(serialize_group(root_group), safe=False)

    except Query.DoesNotExist:
        return JsonResponse({"error": "Query not found"}, status=404)

@login_required
def query_logs_view(request):
    logs = QueryLog.objects.select_related('user').order_by('-executed_at')
    users = User.objects.all()

    selected_user = request.GET.get("user")
    start_date = request.GET.get("start")
    end_date = request.GET.get("end")

    if selected_user:
        logs = logs.filter(user_id=selected_user)
    if start_date:
        logs = logs.filter(executed_at__date__gte=parse_date(start_date))
    if end_date:
        logs = logs.filter(executed_at__date__lte=parse_date(end_date))

    return render(request, 'main/query_logs.html', {
        'logs': logs,
        'users': users,
        'selected_user': selected_user,
        'start_date': start_date,
        'end_date': end_date
    })

@staff_member_required
def admin_dashboard_view(request):
    # You can later add stats like count of unmapped columns, etc.
    return render(request, "main/admin_dashboard.html")

@staff_member_required
def manage_databases_view(request):
    if request.method == "POST":
        if "create" in request.POST:
            unique_id = f"HOSP-{uuid.uuid4().hex[:8].upper()}"

            db_obj = ExternalDatabase.objects.create(
                name=request.POST.get("name"),
                host=request.POST.get("host"),
                port=int(request.POST.get("port", 3306)),
                user=request.POST.get("user"),
                password=request.POST.get("password"),
                db_name=request.POST.get("db_name"),
                hospital_id=unique_id
            )
            messages.success(request, f"Database '{db_obj.name}' created.")
        
        elif "edit" in request.POST:
            db_id = request.POST.get("db_id")
            db = ExternalDatabase.objects.get(id=db_id)

            db.name = request.POST.get("name")
            db.host = request.POST.get("host")
            db.port = int(request.POST.get("port", 3306))
            db.user = request.POST.get("user")
            db.password = request.POST.get("password")
            db.db_name = request.POST.get("db_name")
            db.save()

            messages.success(request, f"Database '{db.name}' updated successfully.")

        elif "introspect" in request.POST:
            db_id = request.POST.get("db_id")
            db = ExternalDatabase.objects.get(id=db_id)
            introspect_database(db)
            messages.success(request, f"Database '{db.name}' introspected.")

        elif "delete" in request.POST:
            db_id = request.POST.get("db_id")
            ExternalDatabase.objects.filter(id=db_id).delete()
            messages.success(request, "Database deleted.")

    dbs = ExternalDatabase.objects.all().order_by("-id")
    fields = ["name", "host", "port", "user", "password", "db_name", "hospital_id"]
    return render(request, "main/manage_databases.html", {
        "databases": dbs,
        "fields": fields
    })

@staff_member_required
def manage_categories_view(request):
    categories = Category.objects.prefetch_related("subcategory_set__parameter_set").order_by("order", "name")
    return render(request, "main/manage_categories.html", {
        "categories": categories
    })

@staff_member_required
def create_category_view(request):
    if request.method == "POST":
        name = request.POST.get("name")
        order = request.POST.get("order", 0)
        Category.objects.create(name=name, order=order)
        return redirect("manage_categories")

@staff_member_required
def create_subcategory_view(request):
    if request.method == "POST":
        name = request.POST.get("name")
        order = request.POST.get("order", 0)
        category_id = request.POST.get("category_id")

        from .models import Category, SubCategory

        category = Category.objects.get(id=category_id)
        SubCategory.objects.create(name=name, order=order, category=category)
        return redirect("manage_categories")

@staff_member_required
def edit_category_view(request, category_id):
    category = get_object_or_404(Category, id=category_id)

    if request.method == "POST":
        category.name = request.POST.get("name")
        category.order = request.POST.get("order", 0)
        category.save()
        return redirect("manage_categories")

@staff_member_required
def delete_category_view(request, category_id):
    Category.objects.filter(id=category_id).delete()
    return redirect("manage_categories")

@staff_member_required
def edit_subcategory_view(request, subcategory_id):
    sub = get_object_or_404(SubCategory, id=subcategory_id)

    if request.method == "POST":
        sub.name = request.POST.get("name")
        sub.order = request.POST.get("order", 0)
        sub.save()
        return redirect("manage_categories")

@staff_member_required
def delete_subcategory_view(request, subcategory_id):
    SubCategory.objects.filter(id=subcategory_id).delete()
    return redirect("manage_categories")

@staff_member_required
def create_parameter_view(request):
    if request.method == "POST":
        subcat_id = request.POST.get("subcategory_id")
        name = request.POST.get("name")
        data_type = request.POST.get("data_type")
        is_phi = bool(request.POST.get("is_phi"))
        is_hhi = bool(request.POST.get("is_hhi"))
        has_unit = bool(request.POST.get("has_unit"))
        unit = request.POST.get("unit") if has_unit else None

        from .models import SubCategory, Parameter
        subcat = SubCategory.objects.get(id=subcat_id)

        Parameter.objects.create(
            name=name,
            data_type=data_type,
            subcategory=subcat,
            is_phi=is_phi,
            is_hhi=is_hhi,
            has_unit=has_unit,
            target_unit=unit
        )
        return redirect("manage_categories")


@staff_member_required
def edit_parameter_view(request, parameter_id):
    param = get_object_or_404(Parameter, id=parameter_id)

    if request.method == "POST":
        param.name = request.POST.get("name")
        param.data_type = request.POST.get("data_type")
        param.has_unit = bool(request.POST.get("has_unit"))
        param.target_unit = request.POST.get("unit") if param.has_unit else None
        param.is_phi = bool(request.POST.get("is_phi"))
        param.is_hhi = bool(request.POST.get("is_hhi"))
        param.save()
        return redirect("manage_categories")

@staff_member_required
def delete_parameter_view(request, parameter_id):
    Parameter.objects.filter(id=parameter_id).delete()
    return redirect("manage_categories")

@csrf_exempt
@staff_member_required
def test_connection_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            connection = pymysql.connect(
                host=data.get("host"),
                user=data.get("user"),
                password=data.get("password"),
                database=data.get("db_name"),
                port=int(data.get("port", 3306))
            )
            connection.close()
            return JsonResponse({"status": "success", "message": "Connection successful!"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)

@staff_member_required
def manage_tables_view(request):
    from .models import ImportedTable, ImportedColumn

    TABLE_TYPE_CHOICES = ImportedTable._meta.get_field("table_type").choices

    if request.method == "POST":
        table_id = request.POST.get("table_id")
        table_type = request.POST.get("table_type")
        study_col = request.POST.get("study_id_column")
        patient_col = request.POST.get("patient_id_column")

        table = ImportedTable.objects.get(id=table_id)
        table.table_type = table_type
        table.study_id_column = study_col or None
        table.patient_id_column = patient_col or None
        table.save()

    tables = ImportedTable.objects.select_related("external_db").all()
    all_columns = {
        tbl.name: ImportedColumn.objects.filter(table=tbl) for tbl in tables
    }

    return render(request, "main/manage_tables.html", {
        "tables": tables,
        "all_columns": all_columns,
        "table_type_choices": TABLE_TYPE_CHOICES,
    })

@staff_member_required
def generate_ids_view(request):
    from .models import ImportedTable
    from django.db.models import Q

    if request.method == "POST":
        return generate_ids_for_table(request)

    # Just load basic info
    tables = ImportedTable.objects.filter(
        Q(study_id_column__isnull=False) | Q(patient_id_column__isnull=False)
    ).select_related("external_db")

    return render(request, "main/generate_ids.html", {
        "tables": tables
    })

def generate_ids_for_table(request):
    from .models import ImportedTable
    import pymysql

    table_id = request.POST.get("table_id")
    tbl = ImportedTable.objects.get(id=table_id)
    db = tbl.external_db

    conn = pymysql.connect(
        host=db.host,
        port=db.port,
        user=db.user,
        password=db.password,
        database=db.db_name
    )
    cursor = conn.cursor()

    columns_to_check = []
    if tbl.study_id_column:
        columns_to_check.append(("STUDY", tbl.study_id_column))
    if tbl.patient_id_column:
        columns_to_check.append(("PATIENT", tbl.patient_id_column))

    for id_type, col in columns_to_check:
        cursor.execute(f"SELECT DISTINCT `{col}` FROM `{tbl.name}` WHERE `{col}` IS NOT NULL")
        values = cursor.fetchall()
        for row in values:
            raw_value = str(row[0])
            get_or_create_anon_id(db.hospital_id, id_type, raw_value)

    cursor.close()
    conn.close()

    messages.success(request, f"Generated anonymous IDs for {tbl.name}")
    return redirect("generate_ids")

def get_or_create_anon_id(hospital_id, id_type, original_value):
    from .models import UniqueIDMap

    # Check if already exists
    existing = UniqueIDMap.objects.filter(
        hospital_id=hospital_id,
        type=id_type,
        original_value=original_value
    ).first()

    if existing:
        return existing.generated_id

    # Build prefix (e.g., HOSP-CC2522CD-S or HOSP-CC2522CD-P)
    prefix = f"{hospital_id}-{'S' if id_type == 'STUDY' else 'P'}"

    # Hash the original value into short string
    short_hash = hashlib.sha256(original_value.encode()).hexdigest()[:7].upper()

    generated_id = f"{prefix}-{short_hash}"

    UniqueIDMap.objects.create(
        hospital_id=hospital_id,
        type=id_type,
        original_value=original_value,
        generated_id=generated_id
    )

    return generated_id


@require_GET
@login_required
def lookup_values(request):
    param_id = request.GET.get("parameter_id")
    try:
        param = Parameter.objects.get(id=param_id)
        column = param.importedcolumn
        db = column.table.external_db

        connection = pymysql.connect(
            host=db.host,
            user=db.user,
            password=db.password,
            database=db.db_name,
            port=db.port
        )

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT DISTINCT `{column.name}` FROM `{column.table.name}` WHERE `{column.name}` IS NOT NULL LIMIT 1000;")
            rows = cursor.fetchall()

        connection.close()
        values = [row[0] for row in rows if row[0] is not None]
        return JsonResponse({"status": "success", "values": values})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)
    
@staff_member_required
@csrf_exempt
def move_parameter_view(request):
    if request.method == "POST":
        from .models import Parameter, SubCategory

        import json
        data = json.loads(request.body)
        param_id = data.get("parameter_id")
        subcategory_id = data.get("subcategory_id")

        try:
            param = Parameter.objects.get(id=param_id)
            sub = SubCategory.objects.get(id=subcategory_id)
            param.subcategory = sub
            param.save()
            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)