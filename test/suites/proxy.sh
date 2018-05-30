test_proxy_device() {
  test_proxy_device_tcp
  test_proxy_device_unix
  test_proxy_device_tcp_unix
  test_proxy_device_unix_tcp
}

test_proxy_device_tcp() {
  ensure_import_testimage
  ensure_has_localhost_remote "${LXD_ADDR}"

  MESSAGE="Proxy device test string"
  HOST_TCP_PORT=$(local_tcp_port)

  lxc launch testimage proxyTester
  lxc config device add proxyTester proxyDev proxy "listen=tcp:127.0.0.1:$HOST_TCP_PORT" connect=tcp:127.0.0.1:4321 bind=host
  nsenter -n -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 4321 > proxyTest.out &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat proxyTest.out)" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly send data from host to container"
    false
  fi

  rm -f proxyTest.out

  lxc restart -f proxyTester
  nsenter -n -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 4321 > proxyTest.out &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat proxyTest.out)" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart on container restart"
    false
  fi

  rm -f proxyTest.out

  lxc config device set proxyTester proxyDev connect tcp:127.0.0.1:1337
  nsenter -n -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 1337 > proxyTest.out &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat proxyTest.out)" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart when config was updated"
    false
  fi

  rm -f proxyTest.out
  lxc delete -f proxyTester
}

test_proxy_device_unix() {
  ensure_import_testimage
  ensure_has_localhost_remote "${LXD_ADDR}"

  MESSAGE="Proxy device test string"
  OUTFILE="${TEST_DIR}/proxyTest.out"
  HOST_SOCK="${TEST_DIR}/host.sock"

  lxc launch testimage proxyTester
  lxc config device add proxyTester proxyDev proxy "listen=unix:${HOST_SOCK}" connect=unix:/tmp/container.sock bind=host
  # prevent nc from complaining about a too long path
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly send data from host to container"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"

  lxc restart -f proxyTester
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart on container restart"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"

  lxc config device set proxyTester proxyDev connect unix:/tmp/container2.sock
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container2.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart when config was updated"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"
  lxc delete -f proxyTester
}

test_proxy_device_tcp_unix() {
  ensure_import_testimage
  ensure_has_localhost_remote "${LXD_ADDR}"

  MESSAGE="Proxy device test string"
  HOST_TCP_PORT=$(local_tcp_port)
  OUTFILE="${TEST_DIR}/proxyTest.out"

  lxc launch testimage proxyTester
  lxc config device add proxyTester proxyDev proxy "listen=tcp:127.0.0.1:${HOST_TCP_PORT}" connect=unix:/tmp/container.sock bind=host
  # prevent nc from complaining about a too long path
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly send data from host to container"
    false
  fi

  rm -f "${OUTFILE}"

  lxc restart -f proxyTester
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart on container restart"
    false
  fi

  rm -f "${OUTFILE}"

  lxc config device set proxyTester proxyDev connect unix:/tmp/container2.sock
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -l -U "${LXD_DIR#$(pwd)/}/containers/proxyTester/rootfs/tmp/container2.sock" > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 127.0.0.1 "${HOST_TCP_PORT}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart when config was updated"
    false
  fi

  rm -f "${OUTFILE}"
  lxc delete -f proxyTester
}

test_proxy_device_unix_tcp() {
  ensure_import_testimage
  ensure_has_localhost_remote "${LXD_ADDR}"

  MESSAGE="Proxy device test string"
  OUTFILE="${TEST_DIR}/proxyTest.out"
  HOST_SOCK="${TEST_DIR}/host.sock"

  lxc launch testimage proxyTester

  lxc config device add proxyTester proxyDev proxy "listen=unix:${HOST_SOCK}" connect=tcp:127.0.0.1:4321 bind=host
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 4321 > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly send data from host to container"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"

  lxc restart -f proxyTester
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 4321 > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart on container restart"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"

  lxc config device set proxyTester proxyDev connect tcp:127.0.0.1:1337
  nsenter -n -U -t "$(lxc query /1.0/containers/proxyTester/state | jq .pid)" -- nc -6 -l 1337 > "${OUTFILE}" &
  sleep 2

  echo "${MESSAGE}" | nc -w1 -U "${HOST_SOCK#$(pwd)/}"

  if [ "$(cat "${OUTFILE}")" != "${MESSAGE}" ]; then
    echo "Proxy device did not properly restart when config was updated"
    false
  fi

  rm -f "${OUTFILE}" "${HOST_SOCK}"
  lxc delete -f proxyTester
}

