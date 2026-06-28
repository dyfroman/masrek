FROM python:3.12-slim
WORKDIR /app

# System deps: bash, curl, DNS utils, git (for testssl.sh), perl (for nikto),
# unzip (for nuclei), openssl (for testssl.sh TLS probes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl dnsutils git unzip perl libnet-ssleay-perl openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Scanner tools (installed in-container — NO docker.sock) ──────────────────

# Nuclei
ARG NUCLEI_VERSION=3.3.7
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -ut 2>/dev/null || true

# Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh

# osv-scanner (SCA: dependency vulnerability scanning)
ARG OSV_SCANNER_VERSION=1.9.1
RUN curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# trivy (SCA + IaC/misconfig scanner)
ARG TRIVY_VERSION=0.71.0
RUN curl -fsSL -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# semgrep (SAST: source code pattern analysis)
ARG SEMGREP_VERSION=1.168.0
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && semgrep --version

# ── Python deps ──────────────────────────────────────────────────────────────

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
