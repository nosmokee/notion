# для хостингов с Docker (Koyeb, свой VPS и т.п.); на Render хватает render.yaml
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt relay.py ./
RUN pip install --no-cache-dir -r requirements.txt
ENV PORT=8080
EXPOSE 8080
CMD ["python", "relay.py"]
