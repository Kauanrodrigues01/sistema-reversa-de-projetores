from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.dependencies import T_Session
from modules.auth.router import router as auth_router
from modules.users.router import router as users_router

app = FastAPI(
    title='Reserva de Projetores',
    description='Projeto para a EEEP Adolfo Ferreira de Sousa',
)
app.include_router(users_router)
app.include_router(auth_router)


@app.get('/', tags=['healthcheck'])
def health_check(session: T_Session):
    try:
        session.execute(select(1))
        return {'status': 'ok', 'database': 'connected'}
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                'status': 'error',
                'database': 'disconnected',
                'error': str(e),
            },
        )
