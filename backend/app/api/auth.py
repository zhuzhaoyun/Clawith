"""Authentication API routes."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException,Query, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_current_user, hash_password, verify_password
from app.database import get_db
from app.models.user import User
from app.schemas.schemas import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
    ResendVerificationRequest,
    IdentityBindRequest,
    IdentityUnbindRequest,
    MultiTenantResponse,
    OAuthAuthorizeResponse,
    OAuthCallbackRequest,
    TenantChoice,
    TokenResponse,
    UserLogin,
    UserOut,
    UserRegister,
    UserUpdate,
)
from sqlalchemy.orm import selectinload

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/registration-config")
async def get_registration_config(db: AsyncSession = Depends(get_db)):
    """Public endpoint — returns registration requirements (no auth needed)."""
    from app.models.system_settings import SystemSetting
    result = await db.execute(select(SystemSetting).where(SystemSetting.key == "invitation_code_enabled"))
    setting = result.scalar_one_or_none()
    enabled = setting.value.get("enabled", False) if setting else False
    return {"invitation_code_required": enabled}


@router.get("/check-duplicate")
async def check_duplicate(
    email: str | None = Query(None, description="Email to check"),
    username: str | None = Query(None, description="Username to check"),
    mobile: str | None = Query(None, description="Mobile to check"),
    tenant_id: uuid.UUID | None = Query(None, description="Tenant context"),
    db: AsyncSession = Depends(get_db),
):
    """Check if email, username or mobile already exists within a tenant context.
    If tenant_id is not provided, it checks globally (legacy/platform-admin behavior).
    """
    result = {"email_exists": False, "username_exists": False, "mobile_exists": False, "conflicts": []}

    if email:
        # Check email within tenant
        query = select(User).where(User.email.ilike(email))
        if tenant_id:
            query = query.where(User.tenant_id == tenant_id)
        
        existing = await db.execute(query)
        if existing.scalar_one_or_none():
            result["email_exists"] = True
            result["conflicts"].append({"type": "email", "message": "Email already registered in this tenant"})

    if username:
        # Check username within tenant
        query = select(User).where(User.username == username)
        if tenant_id:
            query = query.where(User.tenant_id == tenant_id)
            
        existing = await db.execute(query)
        if existing.scalar_one_or_none():
            result["username_exists"] = True
            result["conflicts"].append({"type": "username", "message": "Username already taken in this tenant"})

    if mobile:
        # Normalize mobile before checking
        import re
        normalized_mobile = re.sub(r"[\s\-\+]", "", mobile)
        
        # Check mobile within tenant
        query = select(User).where(User.primary_mobile == normalized_mobile)
        if tenant_id:
            query = query.where(User.tenant_id == tenant_id)
            
        existing = await db.execute(query)
        if existing.scalar_one_or_none():
            result["mobile_exists"] = True
            result["conflicts"].append({"type": "mobile", "message": "Mobile already registered in this tenant"})

    result["has_conflict"] = result["email_exists"] or result["username_exists"] or result["mobile_exists"]
    return result


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    data: UserRegister,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account.

    The first user to register becomes the platform admin automatically and is
    assigned to the default company as org_admin. Subsequent users register
    without a company — they must create or join one via /tenants/self-create
    or /tenants/join.

    Supports optional SSO registration by providing provider + provider_code.
    """
    from app.config import get_settings
    settings = get_settings()
    # Handle SSO registration if provider info provided
    if data.provider and data.provider_code:
        from app.services.auth_registry import auth_provider_registry
        from app.services.registration_service import registration_service

        # Get provider
        auth_provider = await auth_provider_registry.get_provider(db, data.provider)
        if not auth_provider:
            raise HTTPException(status_code=400, detail=f"Provider '{data.provider}' not supported")

        # Perform SSO registration
        user, is_new, error = await registration_service.register_with_sso(
            db, data.provider, data.provider_code, auth_provider
        )

        if error:
            raise HTTPException(status_code=400, detail=error)

        # If no tenant, check for email domain match
        if not user.tenant_id and data.email:
            tenant, _ = await registration_service.get_tenant_for_registration(db, email=data.email)
            if tenant:
                user.tenant_id = tenant.id

        # Generate token
        token = create_access_token(str(user.id), user.role)

        return TokenResponse(
            access_token=token,
            user=UserOut.model_validate(user),
            needs_company_setup=user.tenant_id is None,
        )

    # Regular username/password registration
    from app.services.registration_service import registration_service
    
    # Resolve tenant and role
    from sqlalchemy import func
    user_count_result = await db.execute(select(func.count()).select_from(User))
    is_first_user = user_count_result.scalar() == 0
    
    tenant_uuid = None
    role = "member"
    quota_defaults: dict = {}

    if is_first_user:
        from app.models.tenant import Tenant
        default = await db.execute(select(Tenant).where(Tenant.slug == "default"))
        tenant = default.scalar_one_or_none()
        if not tenant:
            tenant = Tenant(name="Default", slug="default", im_provider="web_only")
            db.add(tenant)
            await db.flush()
        tenant_uuid = tenant.id
        role = "platform_admin"
        quota_defaults = {
            "quota_message_limit": tenant.default_message_limit,
            "quota_message_period": tenant.default_message_period,
            "quota_max_agents": tenant.default_max_agents,
            "quota_agent_ttl_hours": tenant.default_agent_ttl_hours,
        }
    else:
        # Try to resolve tenant via invitation code or email domain
        tenant, _ = await registration_service.get_tenant_for_registration(
            db, email=data.email, invitation_code=data.invitation_code
        )
        if tenant:
            tenant_uuid = tenant.id
            quota_defaults = {
                "quota_message_limit": tenant.default_message_limit,
                "quota_message_period": tenant.default_message_period,
                "quota_max_agents": tenant.default_max_agents,
                "quota_agent_ttl_hours": tenant.default_agent_ttl_hours,
            }

    # Check existing within resolved tenant
    # Only check uniqueness if tenant is resolved (via invitation code or email domain)
    if tenant_uuid:
        query = select(User).where(
            (User.username == data.username) |
            (User.email.ilike(data.email))
        ).where(User.tenant_id == tenant_uuid)

        existing = await db.execute(query)
        if existing.scalars().first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already exists in this tenant")

    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        display_name=data.display_name or data.username,
        role=role,
        tenant_id=tenant_uuid,
        **quota_defaults,
    )
    db.add(user)
    await db.flush()

    # Bind to OrgMember if exists (linking platform user to organization structure)
    await registration_service.bind_org_member(db, user)

    # Auto-create Participant identity for the new user
    from app.models.participant import Participant
    db.add(Participant(
        type="user", ref_id=user.id,
        display_name=user.display_name, avatar_url=user.avatar_url,
    ))
    await db.flush()

    # Seed default agents after first user (platform admin) registration
    if is_first_user:
        await db.commit()  # commit user first so seeder can find the admin
        try:
            from app.services.agent_seeder import seed_default_agents
            await seed_default_agents()
        except Exception as e:
            logger.warning(f"Failed to seed default agents: {e}")

    needs_setup = tenant_uuid is None
    token = create_access_token(str(user.id), user.role)

    # Send email verification for non-SSO registrations
    if not data.provider and settings.SYSTEM_SMTP_HOST and settings.SYSTEM_EMAIL_FROM_ADDRESS:
        try:
            from app.services.email_verification_service import (
                create_email_verification_token,
                build_email_verification_url,
                send_verification_email,
            )

            raw_token, expires_at = await create_email_verification_token(user.id, user.email)
            base_url = settings.PUBLIC_BASE_URL or "http://localhost:3000"
            verify_url = await build_email_verification_url(base_url, raw_token)
            expiry_minutes = int((expires_at - datetime.now(timezone.utc)).total_seconds() // 60)

            background_tasks.add_task(
                send_verification_email,
                user.email,
                user.display_name or user.username,
                verify_url,
                expiry_minutes,
            )
        except Exception as exc:
            logger.warning(f"Failed to send verification email for {user.email}: {exc}")

    return TokenResponse(
        access_token=token,
        user=UserOut.model_validate(user),
        needs_company_setup=needs_setup,
    )


@router.post("/login")
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login with email and password. Supports multi-tenant selection when email matches multiple users."""
    from app.models.tenant import Tenant

    # Query all users by email (login_identifier)
    query = select(User).where(User.email.ilike(data.login_identifier))
    result = await db.execute(query)
    all_users = list(result.scalars().all())

    if not all_users:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # If no tenant_id provided and multiple users exist, return tenant selection
    if not data.tenant_id and len(all_users) > 1:
        # Get tenant info for all users
        tenant_ids = [u.tenant_id for u in all_users if u.tenant_id]
        tenants_map = {}
        if tenant_ids:
            tenants_result = await db.execute(
                select(Tenant).where(Tenant.id.in_(tenant_ids))
            )
            tenants_map = {str(t.id): t for t in tenants_result.scalars().all()}

        tenant_choices = []
        for u in all_users:
            tenant = tenants_map.get(str(u.tenant_id)) if u.tenant_id else None
            tenant_choices.append(TenantChoice(
                tenant_id=u.tenant_id,
                tenant_name=tenant.name if tenant else "No Company",
                tenant_slug=tenant.slug if tenant else "",
            ))

        return MultiTenantResponse(
            requires_tenant_selection=True,
            login_identifier=data.login_identifier,
            tenants=tenant_choices,
        )

    # Filter by tenant_id if provided
    users = all_users
    if data.tenant_id:
        users = [u for u in all_users if u.tenant_id == data.tenant_id]
        if not users:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account does not belong to this organization.",
            )

    # Verify password against any matching user
    user = None
    for u in users:
        if verify_password(data.password, u.password_hash):
            user = u
            break

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Check if user is active
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Check if user's company is disabled
    tenant = None
    if user.tenant_id:
        t_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = t_result.scalar_one_or_none()
        if tenant and not tenant.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your company has been disabled. Please contact the platform administrator.",
            )

    # Check if email is verified (if required)
    from app.config import get_settings
    settings = get_settings()
    if settings.EMAIL_VERIFICATION_REQUIRED and not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your inbox or request a new verification email.",
        )

    needs_setup = user.tenant_id is None
    token = create_access_token(str(user.id), user.role)
    return TokenResponse(
        access_token=token,
        user=UserOut.model_validate(user),
        needs_company_setup=needs_setup,
        tenant_name=tenant.name if tenant else None,
    )


@router.post("/forgot-password")
async def forgot_password(
    data: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Request a password reset link without revealing account existence."""
    from app.config import get_settings
    settings = get_settings()

    if not settings.SYSTEM_SMTP_HOST or not settings.SYSTEM_EMAIL_FROM_ADDRESS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset is currently unavailable (no mail server configured)."
        )

    generic_response = {
        "ok": True,
        "message": "If an account with that email exists, a password reset email has been sent.",
    }

    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        return generic_response

    try:
        from app.services.password_reset_service import build_password_reset_url, create_password_reset_token
        from app.services.system_email_service import (
            get_system_email_config,
            run_background_email_job,
            send_password_reset_email,
        )

        get_system_email_config()
        raw_token, expires_at = await create_password_reset_token(user.id)

        reset_url = await build_password_reset_url(db, raw_token)
        expiry_minutes = int((expires_at - datetime.now(timezone.utc)).total_seconds() // 60)
        background_tasks.add_task(
            run_background_email_job,
            send_password_reset_email,
            user.email,
            user.display_name or user.username,
            reset_url,
            expiry_minutes,
        )
    except Exception as exc:
        logger.warning(f"Failed to process password reset email for {data.email}: {exc}")

    return generic_response


@router.post("/reset-password")
async def reset_password(data: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Reset a password using a valid single-use token."""
    from app.services.password_reset_service import consume_password_reset_token

    token = await consume_password_reset_token(data.token)
    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user_id = token["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user.password_hash = hash_password(data.new_password)
    await db.flush()
    return {"ok": True}


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user profile."""
    return UserOut.model_validate(current_user)


@router.patch("/me", response_model=UserOut)
async def update_me(
    data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile."""
    update_data = data.model_dump(exclude_unset=True)

    # Validate username uniqueness if changing
    if "username" in update_data and update_data["username"] != current_user.username:
        existing = await db.execute(
            select(User).where(
                User.username == update_data["username"],
                User.tenant_id == current_user.tenant_id,
                User.id != current_user.id,
            )
        )
        if existing.scalars().first():
            raise HTTPException(status_code=409, detail="Username already taken in this tenant")

    # Validate email uniqueness within tenant if changing
    if "email" in update_data and update_data["email"] != current_user.email:
        existing = await db.execute(
            select(User).where(
                User.email.ilike(update_data["email"]),
                User.tenant_id == current_user.tenant_id,
                User.id != current_user.id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already registered")

    # Validate mobile uniqueness within tenant if changing
    if "primary_mobile" in update_data and update_data["primary_mobile"] != current_user.primary_mobile:
        existing = await db.execute(
            select(User).where(
                User.primary_mobile == update_data["primary_mobile"],
                User.tenant_id == current_user.tenant_id,
                User.id != current_user.id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Mobile already registered")

    for field, value in update_data.items():
        setattr(current_user, field, value)
    await db.flush()

    # Sync email/phone to OrgMember if changed
    if "email" in update_data or "primary_mobile" in update_data:
        from app.services.registration_service import registration_service
        await registration_service.sync_org_member_contact_from_user(
            db,
            current_user,
            sync_email="email" in update_data,
            sync_phone="primary_mobile" in update_data,
        )

    return UserOut.model_validate(current_user)


@router.put("/me/password")
async def change_password(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user's password. Requires old_password verification.

    Synchronizes password across all users with the same email or phone number.
    """
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Both old_password and new_password are required")

    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    if not verify_password(old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Hash the new password once
    new_hash = hash_password(new_password)

    # Update current user's password
    current_user.password_hash = new_hash

    # Find all users with the same email (case-insensitive) and update their passwords
    if current_user.email:
        same_email_result = await db.execute(
            select(User).where(
                User.email.ilike(current_user.email),
                User.id != current_user.id,
            )
        )
        same_email_users = same_email_result.scalars().all()
        for user in same_email_users:
            user.password_hash = new_hash

    # Find all users with the same primary_mobile and update their passwords
    if current_user.primary_mobile:
        same_phone_result = await db.execute(
            select(User).where(
                User.primary_mobile == current_user.primary_mobile,
                User.id != current_user.id,
            )
        )
        same_phone_users = same_phone_result.scalars().all()
        for user in same_phone_users:
            user.password_hash = new_hash

    await db.flush()
    return {"ok": True}


# ─── SSO/OAuth Endpoints ─────────────────────────────────────────────


@router.get("/providers")
async def list_providers(
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID | None = Query(None, description="Optional tenant ID"),
):
    """List all available identity providers."""
    from app.services.auth_registry import auth_provider_registry

    providers = await auth_provider_registry.list_providers(db, str(tenant_id) if tenant_id else None)
    return [{"id": str(p.id), "provider_type": p.provider_type, "name": p.name, "is_active": p.is_active} for p in providers]


@router.get("/{provider}/authorize", response_model=OAuthAuthorizeResponse)
async def authorize(
    provider: str,
    redirect_uri: str = Query(..., description="OAuth callback URI"),
    state: str = Query("", description="CSRF state parameter"),
    db: AsyncSession = Depends(get_db),
):
    """Start OAuth authorization flow for a provider."""
    from app.services.auth_registry import auth_provider_registry
    from app.services.sso_service import sso_service

    # Get provider
    auth_provider = await auth_provider_registry.get_provider(db, provider)
    if not auth_provider:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' not supported")

    # Generate authorization URL
    try:
        auth_url = await auth_provider.get_authorization_url(redirect_uri, state)
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate authorization URL for {provider}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate authorization URL")

    return OAuthAuthorizeResponse(authorization_url=auth_url)


@router.post("/{provider}/callback", response_model=TokenResponse)
async def oauth_callback(
    provider: str,
    data: OAuthCallbackRequest,
    db: AsyncSession = Depends(get_db),
):
    """Handle OAuth callback and login/register user."""
    from app.services.auth_registry import auth_provider_registry

    # Get provider
    auth_provider = await auth_provider_registry.get_provider(db, provider)
    if not auth_provider:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' not supported")

    try:
        # Exchange code for token
        token_data = await auth_provider.exchange_code_for_token(data.code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token from provider")

        # Get user info
        user_info = await auth_provider.get_user_info(access_token)

        # Find or create user
        user, is_new = await auth_provider.find_or_create_user(db, user_info)

        if not user:
            raise HTTPException(status_code=500, detail="Failed to create user")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is disabled")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed for {provider}: {e}")
        raise HTTPException(status_code=500, detail="OAuth authentication failed")

    # Generate JWT token
    jwt_token = create_access_token(str(user.id), user.role)

    return TokenResponse(
        access_token=jwt_token,
        user=UserOut.model_validate(user),
        needs_company_setup=user.tenant_id is None,
    )


@router.post("/{provider}/bind", response_model=UserOut)
async def bind_identity(
    provider: str,
    data: IdentityBindRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bind an external identity to the current user."""
    from app.services.auth_registry import auth_provider_registry
    from app.services.sso_service import sso_service

    # Get provider
    auth_provider = await auth_provider_registry.get_provider(db, provider)
    if not auth_provider:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' not supported")

    try:
        # Exchange code for token
        token_data = await auth_provider.exchange_code_for_token(data.code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token from provider")

        # Get user info
        user_info = await auth_provider.get_user_info(access_token)

        # Check if identity is already linked to another user
        existing_user = await sso_service.check_duplicate_identity(db, provider, user_info.provider_user_id)
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(
                status_code=409,
                detail="This identity is already linked to another account",
            )

        # Link identity to current user
        await sso_service.link_identity(
            db,
            str(current_user.id),
            provider,
            user_info.provider_user_id,
            user_info.raw_data,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Identity bind failed for {provider}: {e}")
        raise HTTPException(status_code=500, detail="Failed to bind identity")

    return UserOut.model_validate(current_user)


@router.post("/{provider}/unbind", response_model=UserOut)
async def unbind_identity(
    provider: str,
    data: IdentityUnbindRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink an external identity from the current user."""
    from app.services.sso_service import sso_service

    # Unlink identity
    success = await sso_service.unlink_identity(db, str(current_user.id), provider)
    if not success:
        raise HTTPException(status_code=404, detail=f"No linked identity found for provider '{provider}'")

    return UserOut.model_validate(current_user)


# ─── Email Verification Endpoints ──────────────────────────────────────


@router.post("/verify-email")
async def verify_email(data: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    """Verify email address using a token from the verification email."""
    from app.services.email_verification_service import consume_email_verification_token

    token_data = await consume_email_verification_token(data.token)
    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user_id = token_data["user_id"]
    email = token_data["email"]

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    # Check if email matches (case-insensitive)
    if user.email.lower() != email.lower():
        raise HTTPException(status_code=400, detail="Email mismatch")

    user.email_verified = True
    await db.flush()

    return {"ok": True, "message": "Email verified successfully"}


@router.post("/resend-verification")
async def resend_verification(
    data: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Resend email verification link."""
    from app.config import get_settings
    from app.services.email_verification_service import (
        create_email_verification_token,
        build_email_verification_url,
        send_verification_email,
    )

    settings = get_settings()

    # Always return success to prevent email enumeration
    generic_response = {
        "ok": True,
        "message": "If an account with that email exists, a verification email has been sent.",
    }

    if not settings.SYSTEM_SMTP_HOST or not settings.SYSTEM_EMAIL_FROM_ADDRESS:
        return generic_response

    result = await db.execute(select(User).where(User.email.ilike(data.email)))
    user = result.scalar_one_or_none()

    # Don't reveal if user exists
    if not user or user.email_verified:
        return generic_response

    try:
        raw_token, expires_at = await create_email_verification_token(user.id, user.email)
        base_url = settings.PUBLIC_BASE_URL or "http://localhost:3000"
        verify_url = await build_email_verification_url(base_url, raw_token)
        expiry_minutes = int((expires_at - datetime.now(timezone.utc)).total_seconds() // 60)

        background_tasks.add_task(
            send_verification_email,
            user.email,
            user.display_name or user.username,
            verify_url,
            expiry_minutes,
        )
    except Exception as exc:
        logger.warning(f"Failed to resend verification email for {data.email}: {exc}")

    return generic_response
