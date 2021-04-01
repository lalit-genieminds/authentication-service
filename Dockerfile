FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7
WORKDIR /app
COPY ./app /app
RUN pip install requests
RUN pip install fastapi-jwt-auth
RUN pip install python-multipart
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80","--reload"]