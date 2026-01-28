from django.core.exceptions import ValidationError

def validate_roles(value):
    if not isinstance(value, list):
        raise ValidationError("role must be a list of role strings.")
    allowed = {c.value for c in UserRole}
    seen = set()
    for v in value:
        if not isinstance(v, str):
            raise ValidationError("each role must be a string.")
        v_normalized = v.strip().upper()
        if v_normalized not in allowed:
            raise ValidationError(f"invalid role: {v_normalized}")
        if v_normalized in seen:
            raise ValidationError(f"duplicate role: {v_normalized}")
        seen.add(v_normalized)
