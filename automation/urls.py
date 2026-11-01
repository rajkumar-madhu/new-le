from django.urls import path

from . import views

app_name = "automation"

urlpatterns = [
    # runbooks
    path("automation/runbooks/", views.runbooks, name="runbooks"),
    path("automation/runbooks/export.csv", views.runbook_export, name="runbook_export"),
    path("automation/runbooks/new/", views.runbook_create, name="runbook_create"),
    path("automation/runbooks/<int:pk>/", views.runbook_detail, name="runbook_detail"),
    path("automation/runbooks/<int:pk>/edit/", views.runbook_edit, name="runbook_edit"),
    path("automation/runbooks/<int:pk>/reviewed/", views.runbook_reviewed, name="runbook_reviewed"),
    path("automation/runbooks/<int:pk>/delete/", views.runbook_delete, name="runbook_delete"),
    # StackStorm and executions
    path("automation/stackstorm/", views.stackstorm, name="stackstorm"),
    path("automation/stackstorm/trigger/", views.stackstorm_trigger, name="stackstorm_trigger"),
    path("automation/stackstorm/test/", views.stackstorm_test, name="stackstorm_test"),
    path("automation/executions/export.csv", views.execution_export, name="execution_export"),
    path("automation/executions/<int:pk>/", views.execution_detail, name="execution_detail"),
    path("automation/executions/<int:pk>/rerun/", views.execution_rerun, name="execution_rerun"),
    # event workflows (rules)
    path("automation/workflows/", views.workflows, name="workflows"),
    path("automation/workflows/new/", views.rule_create, name="rule_create"),
    path("automation/workflows/<int:pk>/", views.rule_detail, name="rule_detail"),
    path("automation/workflows/<int:pk>/edit/", views.rule_edit, name="rule_edit"),
    path("automation/workflows/<int:pk>/test/", views.rule_test, name="rule_test"),
    path("automation/workflows/<int:pk>/toggle/", views.rule_toggle, name="rule_toggle"),
    path("automation/workflows/<int:pk>/delete/", views.rule_delete, name="rule_delete"),
    # templates
    path("templates/", views.templates, name="templates"),
    path("templates/new/", views.template_create, name="template_create"),
    path("templates/<int:pk>/", views.template_detail, name="template_detail"),
    path("templates/<int:pk>/edit/", views.template_edit, name="template_edit"),
    path("templates/<int:pk>/apply/", views.template_apply, name="template_apply"),
    path("templates/<int:pk>/delete/", views.template_delete, name="template_delete"),
]
