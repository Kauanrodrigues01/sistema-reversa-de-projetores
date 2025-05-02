from projectors.models import Projector


def test_create_model_projector(session):
    projector = Projector(name='EPSON-01')
    session.add(projector)
    session.commit()

    session.refresh(projector)

    assert projector.name == 'EPSON-01'

    session.expire_all()
    db_projector = session.get(Projector, projector.id)
    assert db_projector.id == 1
    assert db_projector.name == 'EPSON-01'
