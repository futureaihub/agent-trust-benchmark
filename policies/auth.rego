package benchmark.auth

default allow = false

allow := true if {
    input.action != "delete"
}

allow := true if {
    input.action == "delete"
    input.environment != "production"
}

allow := true if {
    input.action == "delete"
    input.environment == "production"
    input.role == "admin"
}

default reason = "deny_default"

reason := "deny_delete_production_non_admin" if {
    input.action == "delete"
    input.environment == "production"
    input.role != "admin"
}

reason := "allow_non_production_delete" if {
    input.action == "delete"
    input.environment != "production"
}

reason := "allow_admin_production_delete" if {
    input.action == "delete"
    input.environment == "production"
    input.role == "admin"
}

reason := "allow" if {
    input.action != "delete"
}
