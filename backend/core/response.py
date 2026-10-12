def ok(data=None, message="success"):
    return {"code": 200, "message": message, "data": data if data is not None else {}}


def fail(message, code=400, error_type="BadRequest", detail=None):
    return {
        "code": code,
        "message": message,
        "error": {"type": error_type, "detail": detail or message},
    }


def paginate(items, page, page_size, total):
    return {
        "items": items,
        "pagination": {"page": page, "page_size": page_size, "total": total},
    }

