from sqlalchemy.orm import Mapped, mapped_column

from app.database import table_registry


@table_registry.mapped_as_dataclass
class Projector:
    __tablename__ = 'projectors'

    id: Mapped[int] = mapped_column(init=False, primary_key=True)
    name: Mapped[int] = mapped_column(unique=True)
