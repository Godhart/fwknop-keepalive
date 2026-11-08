# Сторонние компоненты — SPA Keepalive 0.2.0

- libfko / fwknop 2.6.11: https://www.cipherdyne.org/fwknop/download/fwknop-2.6.11.tar.gz
  SHA256 архива, полученного при подготовке: `bcb4e0e2eb5fcece5083d506da8471f68e33fb6b17d9379c71427a95f9ca1ec8`.
  В `android/app/src/main/cpp/vendor` скопированы исходные `.c`/`.h` каталогов
  lib/common, кроме CUnit-тестов. В 0.4.0 cipher_funcs.c и fko_rand_value.c дополнены условной iOS-веткой SPA_USE_ARC4RANDOM (системный CSPRNG); остальные файлы не изменены. COPYING/AUTHORS/CREDITS включены.
  `config.h` взят из upstream Android-примера: версия обновлена до 2.6.11,
  ненужные HAVE_LIBPCAP/HAVE_LIBGDBM убраны. JNI и packet.c — код этого проекта.
  Лицензия GPL-2.0-or-later.
- Gradle Wrapper 8.11.1: https://github.com/gradle/gradle/tree/v8.11.1
  Скрипты и wrapper JAR включены, лицензия `android/gradle/LICENSE`.
  SHA256 дистрибутива зафиксирован в gradle-wrapper.properties.
- AndroidX Activity 1.9.3 и JourneyApps ZXing Embedded 4.3.0 загружаются Gradle;
  Apache-2.0. ZXing выполняет локальное сканирование без Google Play Services.
- Python-зависимости перечислены в tools/requirements*.txt; не встроены в архив.

Добавленный код проекта предоставляется на GPL-2.0-or-later, см. LICENSE.

- ruamel.yaml 0.18.x: сохранение структуры YAML и комментариев, MIT.
- ansible-core 2.17..2.19: необязательная внешняя команда ansible-vault, GPLv3+.
  Документация CLI: https://docs.ansible.com/projects/ansible/latest/cli/ansible-vault.html
