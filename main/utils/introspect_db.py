import MySQLdb
from ..models import ImportedTable, ImportedColumn

def introspect_database(db_obj):
    conn = MySQLdb.connect(
        host=db_obj.host,
        port=db_obj.port,
        user=db_obj.user,
        passwd=db_obj.password,
        db=db_obj.db_name
    )
    cursor = conn.cursor()

    cursor.execute("SHOW TABLES;")
    tables = cursor.fetchall()

    for (table_name,) in tables:
        imported_table, _ = ImportedTable.objects.get_or_create(
            external_db=db_obj,
            name=table_name
        )

        cursor.execute(f"DESCRIBE `{table_name}`;")
        columns = cursor.fetchall()

        for col in columns:
            col_name, col_type = col[0], col[1]
            ImportedColumn.objects.get_or_create(
                table=imported_table,
                name=col_name,
                defaults={
                    'data_type': col_type,
                }
            )

    conn.close()
