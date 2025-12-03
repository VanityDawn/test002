import pytest
from app.crawler import crawl_baidu

class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.status_code = 200
    def raise_for_status(self):
        return None

def test_crawl_baidu_parse(monkeypatch):
    html = '''
    <div class="result">
      <h3><a href="https://example.com/a">标题A</a></h3>
      <div class="c-abstract">这是概要A</div>
      <img src="https://example.com/a.jpg"/>
      <span class="source">来源A</span>
    </div>
    <div class="result">
      <h3><a href="https://example.com/b">标题B</a></h3>
      <div class="c-abstract">这是概要B</div>
    </div>
    '''
    def fake_get(url, params=None, headers=None, cookies=None, timeout=None):
        return DummyResponse(html)
    monkeypatch.setattr('requests.get', fake_get)
    items = crawl_baidu('测试', limit=5)
    assert len(items) == 2
    assert items[0]['标题'] == '标题A'
    assert items[0]['概要'] == '这是概要A'
    assert items[0]['封面'] == 'https://example.com/a.jpg'
    assert items[0]['原始URL'] == 'https://example.com/a'
    assert items[0]['来源'] == '来源A'

def test_crawl_baidu_parse_c_container(monkeypatch):
    html = '''
    <div id="content_left">
      <div class="c-container">
        <h3 class="t"><a href="https://example.com/c">标题C</a></h3>
        <div class="c-abstract">这是概要C</div>
        <span class="c-color-gray">来源C</span>
      </div>
    </div>
    '''
    def fake_get(url, params=None, headers=None, cookies=None, timeout=None):
        return DummyResponse(html)
    monkeypatch.setattr('requests.get', fake_get)
    items = crawl_baidu('测试', limit=5)
    assert len(items) == 1
    assert items[0]['标题'] == '标题C'
    assert items[0]['概要'] == '这是概要C'
    assert items[0]['来源'] == '来源C'
