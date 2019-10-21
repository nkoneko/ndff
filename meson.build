project('ndff', 'c',
    version: '0.1.0',
    license: 'GPL'
)

deps = [
    dependency('libndpi', versions: '>=2.8'),
    dependency('msgpack', versions: '>=3.2'),
    dependency('json-c', fallback: ['json-c', 'json-c_dep']),
    dependency('libpcap', versions: '>=1.9')
]
executable('ndff', 'ndff.c', dependencies: deps)
