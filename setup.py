from setuptools import setup, find_packages

setup(
    name='center_client',
    version='1.0.0',
    packages=find_packages(),
    install_requires=['requests', 'flask'],
    description='微服务注册客户端 - 自动注册、心跳、健康检查',
    python_requires='>=3.8',
)