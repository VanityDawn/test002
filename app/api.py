from flask import Blueprint, request, jsonify
import os
from .crawler import crawl_baidu

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.get('/search')
def search():
    wd = request.args.get('wd') or ''
    limit = int(request.args.get('limit') or 10)
    pages = int(request.args.get('pages') or 1)
    per = int(request.args.get('per') or 10)
    if not wd:
        return jsonify({'items': [], 'count': 0})
    # 可选从环境读取 Cookie/Headers
    cookie = os.environ.get('BAIDU_COOKIE')
    headers = None
    try:
        items = crawl_baidu(wd, headers=headers, cookies={'cookie': cookie} if cookie else None, limit=limit, pages=pages, per_page=per)
        return jsonify({'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'items': [], 'count': 0, 'error': str(e)}), 200
