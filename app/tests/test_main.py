from unittest.mock import MagicMock

from fastapi import status
from app.database import get_session
from app.main import app

def test_health_check(client):
    """Test the health check endpoint"""
    response = client.get('/')
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'status': 'ok', 'database': 'connected'}


def test_health_check_database_error(client):
    """Test health check when database connection fails"""
    mock_session = MagicMock()
    mock_session.execute.side_effect = Exception('Database connection error')
    
    # Overriding the dependency to simulate a database error
    app.dependency_overrides[get_session] = lambda: mock_session

    response = client.get('/')

    # Resetting the dependency override to avoid side effects
    app.dependency_overrides = {}

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {
        'status': 'error',
        'database': 'disconnected',
        'error': 'Database connection error'
    }
