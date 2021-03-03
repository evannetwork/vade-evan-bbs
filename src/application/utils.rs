use uuid::Uuid;

pub fn generate_uuid() -> String {
    return format!("{}", Uuid::new_v4());
}
