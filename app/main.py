from fastapi import FastAPI

from users.router import router

app = FastAPI(
    title='Reserva de Projetores',
    description='Projeto para a EEEP Adolfo Ferreira de Sousa',
)
app.include_router(router)
