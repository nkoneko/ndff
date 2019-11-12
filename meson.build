project('ndff', 'cpp',
    version: '0.1.0',
    license: 'GPL',
    default_options: ['cpp_std=c++2a']
)

ndpi_deps = dependency('libndpi', versions: '>=2.8')
msgpack_deps = dependency('msgpack', versions: '>=3.2')
json_deps = dependency('json-c', fallback: ['json-c', 'json_deps'])
pcap_deps = dependency('libpcap', versions: '>=1.9')
gtest_deps = dependency('gtest'm fallback: ['gtest', 'gtest_deps'])

inc = include_directories('include')
libndff = static_library('libndff.a', 'ndff.cpp',
    include_directories: inc,
    dependencies:[
       ndpi_deps,
        msgpack_deps,
        json_deps,
        pcap_deps     
    ])

executable('ndff', 'main.cpp', include_directories: inc, link_with: libndff)
test = executable('ndff_test', 'test.cpp', include_directories: inc, link_with: libndff)
test('TestNdff', test)
