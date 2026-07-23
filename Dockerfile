FROM python:3.11-slim
 
WORKDIR /app
 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
COPY capstone_contract_audit_v2.py .
COPY policies.json .
 
ENV PORT=8080
ENV MOCK=1
EXPOSE 8080
 
CMD ["python", "capstone_contract_audit_v2.py", "serve"]
 

