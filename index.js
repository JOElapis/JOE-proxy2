app.get('/api/proxy', requireAuth, async (req, res) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    let target = await validateTarget(req.query.url);
    let upstream;

    for (let redirects = 0; redirects <= 5; redirects += 1) {
      upstream = await fetch(target, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'user-agent': 'Mozilla/5.0 (compatible; ProxyOnly/1.0)',
          accept: req.headers.accept || '*/*',
          ...(req.headers.range ? { range: req.headers.range } : {}),
        },
      });

      if (![301, 302, 303, 307, 308].includes(upstream.status)) break;
      const location = upstream.headers.get('location');
      if (!location || redirects === 5) throw new Error('リダイレクトが多すぎます。');
      target = await validateTarget(new URL(location, target).href);
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const body = Buffer.from(await upstream.arrayBuffer());

    res.status(upstream.status);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store');

    if (contentType.toLowerCase().includes('text/html')) {
      res.send(rewriteHtml(body.toString('utf8'), target.href));
    } else {
      res.send(body);
    }
  } catch (error) {
    console.error('Proxy request failed:', error.message);
    if (!res.headersSent) res.status(400).json({ error: error.message });
  } finally {
    clearTimeout(timer);
  }
});
