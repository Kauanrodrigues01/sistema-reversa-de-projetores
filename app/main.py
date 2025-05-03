from fastapi import FastAPI

from auth.router import router as auth_router
from users.router import router as users_router

app = FastAPI(
    title='Reserva de Projetores',
    description='Projeto para a EEEP Adolfo Ferreira de Sousa',
)
app.include_router(users_router)
app.include_router(auth_router)
