from django.contrib import admin

# Register your models here.
from .models import Message
from .models import ExternalDatabase, Category, SubCategory, Parameter, ColumnMapping
from .models import ImportedTable, ImportedColumn
from django.contrib import messages
from .utils.introspect_db import introspect_database

admin.site.register(Message)

@admin.action(description="Introspect and Import Schema")
def run_introspection(modeladmin, request, queryset):
    for db in queryset:
        introspect_database(db)
    messages.success(request, "Schema introspection complete.")

@admin.register(ExternalDatabase)
class ExternalDatabaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'host', 'port', 'hospital_id')
    actions = [run_introspection]

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'order')

@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'order')
    list_filter = ('category',)

@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ('name', 'subcategory', 'data_type', 'is_phi', 'is_hhi')
    list_filter = ('data_type', 'is_phi', 'is_hhi')

# @admin.register(ColumnMapping)
# class ColumnMappingAdmin(admin.ModelAdmin):
#     list_display = ('external_db', 'column_name', 'parameter')
#     list_filter = ('external_db',)


@admin.register(ImportedTable)
class ImportedTableAdmin(admin.ModelAdmin):
    list_display = ('name', 'external_db')
    list_filter = ('external_db',)

@admin.register(ImportedColumn)
class ImportedColumnAdmin(admin.ModelAdmin):
    list_display = ('name', 'table', 'data_type', 'is_phi', 'is_hhi', 'mapped_parameter')
    list_filter = ('data_type', 'is_phi', 'is_hhi', 'table__external_db')
