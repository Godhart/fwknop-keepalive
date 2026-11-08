def render_rc(c):
    fields = {
        'SPA_SERVER':c['server'], 'SPA_SERVER_PORT':c['spa_port'],
        'SPA_SERVER_PROTO':'udp', 'ACCESS':c['access'],
        'ALLOW_IP':'0.0.0.0' if c['allow_ip']=='source' else c['allow_ip'],
        'SPOOF_USER':c['username'], 'FW_TIMEOUT':c['access_timeout_seconds'],
        'KEY_BASE64':c['key_base64'], 'HMAC_KEY_BASE64':c['hmac_key_base64'],
        'USE_HMAC':'Y','HMAC_DIGEST_TYPE':'SHA256','DIGEST_TYPE':'SHA256',
        'ENCRYPTION_MODE':'CBC','SERVER_RESOLVE_IPV4':'Y'}
    rc = '[keepalive]\n' + '\n'.join(f'{k} {v}' for k,v in fields.items()) + '\n'
    return rc
