from django.urls import path, re_path, include
from . import views
from .views import manage_tables_view, test_connection_view, move_parameter_view, create_parameter_view, edit_parameter_view, delete_parameter_view, edit_subcategory_view, delete_subcategory_view, edit_category_view, delete_category_view, create_subcategory_view, create_category_view, manage_categories_view, manage_databases_view, admin_dashboard_view, register, logout_view, column_mapping_view, map_column, run_query, query_builder_view, save_query_structure, unassign_column
from django.contrib.auth import views as auth_views, logout
from django.contrib.auth.views import LogoutView
from django.views.generic import RedirectView
from django.shortcuts import redirect

urlpatterns = [
    path("column-mapping/", column_mapping_view, name="column-mapping"),
]

urlpatterns += [
    path("register/", register, name="register"),
]

urlpatterns += [
    path("login/", auth_views.LoginView.as_view(template_name="main/login.html"), name="login"),
    path("logout/", logout_view, name="logout"),
]

urlpatterns += [
    path("map-column/", map_column, name="map-column"),
    path("unassign-column/", unassign_column, name="unassign-column"),
]

urlpatterns += [
    path("run-query/", views.run_query, name="run-query"),
    path("query-builder/", query_builder_view, name="query-builder"),
    path("save-query-structure/", save_query_structure, name="save-query-structure"),
    path("load-query/<int:query_id>/", views.load_query, name="load-query"),
    path('list-queries/', views.list_queries, name='list_queries'),
    path('query-logs/', views.query_logs_view, name='query_logs'),
]

urlpatterns += [
    path("admin-dashboard/", admin_dashboard_view, name="admin_dashboard"),
    path("admin-databases/", manage_databases_view, name="manage_databases"),
    path("admin-categories/", manage_categories_view, name="manage_categories"),
    path("admin-categories/create-category/", create_category_view, name="create_category"),
    path("admin-categories/create-subcategory/", create_subcategory_view, name="create_subcategory"),
    path("admin-categories/create-parameter/", create_parameter_view, name="create_parameter"),
    path("admin-categories/edit-category/<int:category_id>/", edit_category_view, name="edit_category"),
    path("admin-categories/delete-category/<int:category_id>/", delete_category_view, name="delete_category"),
    path("admin-categories/edit-subcategory/<int:subcategory_id>/", edit_subcategory_view, name="edit_subcategory"),
    path("admin-categories/delete-subcategory/<int:subcategory_id>/", delete_subcategory_view, name="delete_subcategory"),
    path("admin-categories/edit-parameter/<int:parameter_id>/", edit_parameter_view, name="edit_parameter"),
    path("admin-categories/delete-parameter/<int:parameter_id>/", delete_parameter_view, name="delete_parameter"),
    path("admin-categories/move-parameter/", move_parameter_view, name="move_parameter"),
    path("lookup-values/", views.lookup_values, name="lookup-values"),
    path("admin-databases/test-connection/", test_connection_view, name="test_connection"),
    path("admin-tables/", manage_tables_view, name="manage_tables"),
    path("generate-ids/", views.generate_ids_view, name="generate_ids"),
]

