import uvicorn

from aliyun_ip_gate.web import app


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=app.state.web_config.port)
