import requests
from bs4 import BeautifulSoup

def crawl_baidu(keyword, headers=None, cookies=None, limit=10, pages=1, per_page=10):
    url = 'https://www.baidu.com/s'
    params = {'wd': keyword, 'ie': 'utf-8'}
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0 Safari/537.36',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://www.baidu.com/'
    }
    if headers:
        default_headers.update(headers)
    items = []
    for p in range(max(1, pages)):
        page_params = dict(params)
        page_params.update({'pn': p * per_page, 'rn': per_page})
        r = requests.get(url, params=page_params, headers=default_headers, cookies=cookies, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        nodes = soup.select('#content_left .c-container, div.result, div.new-pmd')
        for node in nodes:
            a = node.select_one('h3 a, h3.t a, a.c-title, a')
            title = a.get_text(strip=True) if a else ''
            href = a.get('href') if a else ''
            summary_node = node.select_one('.c-abstract,.content_description,.summary,.content__des')
            summary = summary_node.get_text(strip=True) if summary_node else ''
            img = node.select_one('img')
            cover = img.get('src') if img else ''
            source_node = node.select_one('.source,.c-span-last,.c-gap-left-small,.c-color-gray')
            source = source_node.get_text(strip=True) if source_node else '百度搜索'
            if title or href:
                items.append({
                    '标题': title,
                    '概要': summary,
                    '封面': cover,
                    '原始URL': href,
                    '来源': source
                })
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
    return items

