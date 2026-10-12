from fastapi import APIRouter

from core.response import ok
from modules.demo.service import reset_demo_data

router = APIRouter(tags=["demo"])


@router.post("/demo/reset")
def reset_demo():
    return ok(reset_demo_data(), message="演示数据已重置")
