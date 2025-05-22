from django.db import models

class Message(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class ExternalDatabase(models.Model):
    name = models.CharField(max_length=100)
    host = models.CharField(max_length=255)
    port = models.IntegerField(default=3306)
    user = models.CharField(max_length=100)
    password = models.CharField(max_length=100)  # encrypted in real-world
    db_name = models.CharField(max_length=100)
    hospital_id = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Category(models.Model):
    name = models.CharField(max_length=100)
    order = models.IntegerField(default=0)

    def __str__(self):
        return self.name

class SubCategory(models.Model):
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    order = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.category.name} > {self.name}"

class Parameter(models.Model):
    name = models.CharField(max_length=100)
    data_type = models.CharField(max_length=50, choices=[
        ('text', 'Text'),
        ('integer', 'Integer'),
        ('date', 'Date'),
        ('float', 'Float'),
    ])
    has_unit = models.BooleanField(default=False)
    target_unit = models.CharField(max_length=50, null=True, blank=True)
    subcategory = models.ForeignKey(SubCategory, on_delete=models.CASCADE)
    is_phi = models.BooleanField(default=False)
    is_hhi = models.BooleanField(default=False)

    # Inside Parameter model
    @property
    def mapped_column(self):
        return getattr(self, 'importedcolumn', None)
        
    def __str__(self):
        return self.name

class ColumnMapping(models.Model):
    external_db = models.ForeignKey(ExternalDatabase, on_delete=models.CASCADE)
    parameter = models.ForeignKey(Parameter, on_delete=models.CASCADE)
    column_name = models.CharField(max_length=100)
    source_unit = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return f"{self.column_name} → {self.parameter.name} ({self.external_db.name})"

class ImportedTable(models.Model):
    external_db = models.ForeignKey(ExternalDatabase, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    table_type = models.CharField(
        max_length=20,
        choices=[("patient", "Patient"), ("study", "Study"), ("study_sub", "Study Sub")],
        default="study_sub"
    )
    study_id_column = models.CharField(max_length=100, null=True, blank=True)
    patient_id_column = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.external_db.name})"

class ImportedColumn(models.Model):
    table = models.ForeignKey(ImportedTable, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    data_type = models.CharField(max_length=50)
    is_phi = models.BooleanField(default=False)
    is_hhi = models.BooleanField(default=False)
    mapped_parameter = models.OneToOneField(Parameter, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.name} ({self.table.name})"

class Query(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class QueryGroup(models.Model):
    position = models.IntegerField(default=0)
    query = models.ForeignKey(Query, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    logic = models.CharField(null=True, max_length=20, choices=[("AND", "AND"), ("OR", "OR"), ("AND NOT", "AND NOT")])

class QueryCondition(models.Model):
    position = models.IntegerField(default=0)
    group = models.ForeignKey(QueryGroup, on_delete=models.CASCADE)
    parameter = models.ForeignKey(Parameter, on_delete=models.CASCADE)
    operator = models.CharField(max_length=50)
    value = models.TextField(null=True, blank=True)
    value0 = models.TextField(null=True, blank=True)
    value1 = models.TextField(null=True, blank=True)
    logic = models.CharField(null=True, max_length=20, default="AND")


class UniqueIDMap(models.Model):
    hospital_id = models.CharField(max_length=100)
    type = models.CharField(max_length=10, choices=[('STUDY', 'Study'), ('PATIENT', 'Patient')])
    original_value = models.CharField(max_length=255)
    generated_id = models.CharField(max_length=255)

class QueryLog(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    executed_at = models.DateTimeField(auto_now_add=True)
    query_structure = models.JSONField()
    output_parameters = models.JSONField()