from src.organizations import services as org_services, selectors as org_selectors
from src.users import services as user_services


def org_validate(*, organization_id, validated_by):
    return org_services.organization_validate(
        organization_id=organization_id, validated_by=validated_by
    )


def org_refuse(*, organization_id, refused_by, reason: str):
    return org_services.organization_refuse(
        organization_id=organization_id, refused_by=refused_by, reason=reason
    )


def org_toggle_activation(*, organization_id, toggled_by):
    return org_services.organization_toggle_activation(
        organization_id=organization_id, toggled_by=toggled_by
    )


def org_delete(*, organization_id, deleted_by):
    return org_services.organization_delete(
        organization_id=organization_id, deleted_by=deleted_by
    )


def user_resend_invite(*, user_id, requested_by):
    return user_services.user_resend_invitation(
        user_id=user_id, requested_by=requested_by
    )
