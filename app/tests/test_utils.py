import pytest
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.utils import get_object_or_404, auth_required, verify_duplicate_email
from app.dependencies import T_User
from modules.users.models import User


def test_get_object_or_404_returns_object_when_found(session: Session, user: User):
    """Test get_object_or_404 returns the object when it exists in the database"""
    result = get_object_or_404(User, user.id, session)
    assert result == user
    assert isinstance(result, User)


def test_get_object_or_404_raises_404_when_not_found(session: Session):
    """Test get_object_or_404 raises HTTP 404 when the object is not found"""
    with pytest.raises(HTTPException) as exc_info:
        get_object_or_404(User, 999999, session)
    
    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    assert exc_info.value.detail == 'Object not found'


def test_get_object_or_404_custom_detail_message(session: Session):
    """Test get_object_or_404 raises HTTP 404 with custom detail message"""
    custom_detail = "Custom not found message"
    with pytest.raises(HTTPException) as exc_info:
        get_object_or_404(User, 999999, session, detail=custom_detail)
    
    assert exc_info.value.detail == custom_detail


def test_auth_required_allows_authenticated_user(user: T_User):
    """Test auth_required decorator allows access when user is authenticated"""
    @auth_required
    def mock_function(user, *args, **kwargs):
        return "success"
    
    result = mock_function(user)
    assert result == "success"


def test_auth_required_blocks_unauthenticated_user():
    """Test auth_required decorator blocks access when user is None"""
    @auth_required
    def mock_function(user, *args, **kwargs):
        return "success"
    
    with pytest.raises(HTTPException) as exc_info:
        mock_function(None)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == 'Not authenticated'


def test_auth_required_preserves_function_metadata():
    """Test auth_required decorator preserves function name and docstring"""
    def original_function(user, *args, **kwargs):
        """Original docstring"""
        return "success"
    
    decorated = auth_required(original_function)
    
    assert decorated.__name__ == "original_function"
    assert decorated.__doc__ == "Original docstring"


def test_verify_duplicate_email_allows_unique_email(session: Session, user: User):
    """Test verify_duplicate_email does not raise error for a unique email"""
    verify_duplicate_email("new@email.com", session)


def test_verify_duplicate_email_blocks_duplicate_email(session: Session, user: User):
    """Test verify_duplicate_email raises 400 for existing email"""
    with pytest.raises(HTTPException) as exc_info:
        verify_duplicate_email(user.email, session)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == 'Email already registered'


def test_verify_duplicate_email_allows_own_email_on_update(session: Session, user: User):
    """Test verify_duplicate_email allows user to keep their own email"""
    verify_duplicate_email(user.email, session, user_id=user.id)


def test_verify_duplicate_email_blocks_other_user_email_on_update(session: Session, user: User, user2: User):
    """Test verify_duplicate_email blocks duplicate email from another user during update"""
    with pytest.raises(HTTPException) as exc_info:
        verify_duplicate_email(user2.email, session, user_id=user.id)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == 'Email already registered'


def test_verify_duplicate_email_handles_none_user_id(session: Session, user: User):
    """Test verify_duplicate_email blocks duplicate email if user_id is None"""
    with pytest.raises(HTTPException) as exc_info:
        verify_duplicate_email(user.email, session, user_id=None)
    
    assert exc_info.value.detail == 'Email already registered'
