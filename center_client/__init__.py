"""
center_client - 子服务注册客户端 + 网关身份校验
使用方法:
    from flask import Flask
    from center_client import ServiceConfig, register_service

    app = Flask(__name__)

    config = ServiceConfig(
        center_url="http://127.0.0.1:9000",
        service_name="stock-zhangsan",
        host="127.0.0.1",
        port=5088,
        gw_secret="",            # 注册后由中心动态下发, 无需手动填
        routes=["/", "/api/quotes", "/api/kline", "/option-expiry"]
    )

    register_service(app, config)

    # 然后正常写业务路由...
    @app.route("/api/quotes")
    def quotes(): ...
"""
import threading, time, requests, hmac, hashlib, base64, json as _json, signal, sys
from flask import request, jsonify

class ServiceConfig:
    def __init__(self, center_url, service_name, host, port, routes=None, gw_secret=''):
        self.center_url = center_url.rstrip('/')
        self.service_name = service_name
        self.host = host
        self.port = port
        self.routes = ','.join(routes) if routes else ''
        self.gw_secret = gw_secret

class ServiceClient:
    """管理注册、心跳、撤销的客户端"""
    def __init__(self, config):
        self.config = config
        self.token = None
        self.gw_secret = config.gw_secret
        self._running = False
        self._heartbeat_thread = None
        self._stopped = False   # 标记是否已被吊销

    def register(self):
        """向主服务注册"""
        try:
            resp = requests.post(
                f"{self.config.center_url}/register",
                json={
                    'service_name': self.config.service_name,
                    'host': self.config.host,
                    'port': self.config.port,
                    'routes': self.config.routes
                },
                timeout=10
            )
            data = resp.json()
            if data.get('code') == 0:
                self.token = data['service_token']
                # 中心动态下发的专属密钥, 用于校验网关下发的身份令牌
                self.gw_secret = data.get('gw_secret', '') or self.config.gw_secret
                print(f"[注册] ✓ 已注册到 {self.config.center_url}, token={self.token[:8]}..., gw_secret={'已下发' if self.gw_secret else '无'}", flush=True)
                return True
            else:
                print(f"[注册] ✗ 注册失败: {data.get('msg')}")
                return False
        except Exception as e:
            print(f"[注册] ✗ 连接主服务失败: {e}")
            return False

    def unregister(self):
        """注销"""
        if self.token:
            try:
                requests.post(
                    f"{self.config.center_url}/unregister",
                    json={'service_token': self.token},
                    timeout=5
                )
            except:
                pass
            print("[注销] 已向主服务发送注销请求")

    def start_heartbeat(self):
        """启动心跳线程"""
        self._running = True
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def _heartbeat_loop(self):
        """心跳循环: 每10秒向主服务报告存活(主服务主动探测, 这里做被动确认)"""
        # 心跳由主服务主动探测 /health 端点
        # 这里只是维持线程存活, 实际健康检查在 /health 路由中
        while self._running:
            time.sleep(5)
            if self._stopped:
                print("[心跳] 服务已被吊销, 停止对外服务")
                self._running = False

    def stop(self):
        """优雅下线"""
        self._running = False
        self.unregister()


def verify_gw_token(token, secret, expected_aud):
    """校验网关下发的身份令牌: 签名 + 有效期 + 受众(service_name)"""
    if not token or not secret:
        return False
    try:
        body, sig = token.rsplit('.', 1)
        exp_sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_sig, sig):
            return False
        payload = _json.loads(base64.urlsafe_b64decode(body))
        if payload.get('exp', 0) < time.time():
            return False
        if payload.get('aud') != expected_aud:
            return False
        return True
    except Exception:
        return False


def register_service(app, config):
    """
    将 center_client 功能注入到 Flask app 中
    - 自动暴露 /health 端点(供主服务探活)
    - 启动时自动注册到主服务(并取回专属 gw_secret)
    - before_request 全局校验网关身份令牌(排除 /health)
    """
    client = ServiceClient(config)

    @app.route('/health')
    def health_check():
        """健康检查端点, 供主服务探测"""
        req_token = request.args.get('token', '')
        if not client._running or client._stopped:
            return jsonify({'alive': False, 'msg': 'service stopped'}), 503

        if req_token and req_token != client.token:
            # token 不匹配：仅记录告警并返回 403，不再自锁 _stopped(避免单次探测失败永久掐死服务)
            print(f"[健康检查] token 不匹配(探测={str(req_token)[:8]}... 本地={str(client.token)[:8]}...)，返回 403", flush=True)
            return jsonify({'alive': False, 'msg': 'token invalid'}), 403

        return jsonify({'alive': True, 'service': config.service_name})

    @app.before_request
    def _gw_auth_guard():
        # /health 由中心探活, 不走网关令牌校验
        if request.path == '/health':
            return None
        if not client.gw_secret:
            # 未连中心 / 本地纯开发: 放行但告警一次
            if not getattr(_gw_auth_guard, '_warned', False):
                print("[校验] 未配置 gw_secret, 跳过网关令牌校验 (本地开发 / 未连中心)")
                _gw_auth_guard._warned = True
            return None
        token = request.headers.get('X-Gw-Token', '')
        if not verify_gw_token(token, client.gw_secret, config.service_name):
            return jsonify({'code': -1, 'msg': '网关身份校验失败'}), 403
        return None

    # 启动时注册
    def _on_startup():
        if client.register():
            client.start_heartbeat()
            print(f"[{config.service_name}] 服务已上线, 端口: {config.port}")
        else:
            print(f"[{config.service_name}] 注册失败, 仍可独立运行(不依赖主服务)")

    _on_startup()

    # 存储 client 引用到 app 上供高级用法
    app._service_client = client

    return client
