from users.models import User


def test_create_model_user(session):
    user = User(username='test', password='secret')
    session.add(user)
    session.commit()

    session.refresh(user)

    assert user.username == 'test'
    assert user.password == 'secret'
    assert user.id is not None
    assert user.created_at is not None
    assert user.id == 1

    session.expire_all()
    db_user = session.get(User, user.id)
    assert db_user.id == 1
    assert db_user.username == 'test'
