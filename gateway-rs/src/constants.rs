//! Shared platform constants retained from the Python backend.

pub struct Headers;
impl Headers {
    pub const REQUEST_ID: &str = "request_id";
}

pub struct Defaults;
impl Defaults {
    pub const PAGE: usize = 1;
    pub const PAGE_SIZE: usize = 10;
    pub const MAX_PAGE_SIZE_ENV: &str = "MAX_PAGE_SIZE";
    pub const MAX_PAGE_SIZE_DEFAULT: usize = 200;
    pub const MAX_MULTIPART_SIZE_BYTES_ENV: &str = "MAX_MULTIPART_SIZE_BYTES";
    pub const MAX_MULTIPART_SIZE_BYTES_DEFAULT: usize = 5_242_880;
}

pub struct Roles;
impl Roles {
    pub const MANAGE_USERS: &str = "manage_users";
    pub const MANAGE_APIS: &str = "manage_apis";
    pub const MANAGE_GROUPS: &str = "manage_groups";
    pub const MANAGE_ENDPOINTS: &str = "manage_endpoints";
    pub const VIEW_LOGS: &str = "view_logs";
    pub const EXPORT_LOGS: &str = "export_logs";
    pub const MANAGE_ROLES: &str = "manage_roles";
}

pub struct ErrorCodes;
impl ErrorCodes {
    pub const UNEXPECTED: &str = "GTW999";
    pub const HTTP_EXCEPTION: &str = "GTW998";
    pub const GRPC_GENERATION_FAILED: &str = "GTW012";
    pub const PATH_VALIDATION: &str = "GTW013";
    pub const API_NOT_FOUND: &str = "API002";
    pub const AUTH_REQUIRED: &str = "AUTH001";
    pub const REQUEST_TOO_LARGE: &str = "REQ002";
    pub const REQUEST_FILE_TYPE: &str = "REQ003";
    pub const PAGE_SIZE: &str = "PAG001";
}

pub struct Messages;
impl Messages {
    pub const UNEXPECTED: &str = "An unexpected error occurred";
    pub const FILE_TOO_LARGE: &str = "Uploaded file too large";
    pub const ONLY_PROTO_ALLOWED: &str = "Only .proto files are allowed";
    pub const PERMISSION_MANAGE_APIS: &str = "User does not have permission to manage APIs";
    pub const GRPC_GEN_FAILED: &str = "Failed to generate gRPC code";
    pub const PAGE_TOO_LARGE: &str = "Page size exceeds maximum limit";
    pub const INVALID_PAGING: &str = "Invalid page or page size";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_python_defaults_and_wire_constants() {
        assert_eq!(Headers::REQUEST_ID, "request_id");
        assert_eq!(Defaults::PAGE_SIZE, 10);
        assert_eq!(Defaults::MAX_PAGE_SIZE_DEFAULT, 200);
        assert_eq!(Defaults::MAX_MULTIPART_SIZE_BYTES_DEFAULT, 5_242_880);
        assert_eq!(ErrorCodes::HTTP_EXCEPTION, "GTW998");
        assert_eq!(Messages::FILE_TOO_LARGE, "Uploaded file too large");
    }
}
