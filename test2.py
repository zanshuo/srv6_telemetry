#!/usr/bin/python3
import time
from concurrent.futures import ThreadPoolExecutor
from gevent import monkey;monkey.patch_all()
import gevent
import os
def test(port):
    # command = "get_time_elapsed"
    # start_time = time.time()
    # echo_display = os.popen("""simple_switch_CLI --thrift-port {0} <<EOF
    #                              {1}
    #                             EOF""".format(port, command)).read()
    # end_time = time.time()
    # # delta = end_time-start_time
    # print(port, start_time, time.time(), sep=":")
    # print(echo_display)
    print(port, time.time(),os.getpid())


if __name__ == "__main__":
    # res_l=list()
    # p1 = ThreadPoolExecutor(5)
    # t1 = p1.submit(test, 9090)
    # t2 = p1.submit(test, 9091)
    # p1.shutdown()
    # for x in range(5):
    p1 = gevent.spawn(test, 9091)
    # p2 = gevent.spawn(test, 9091)
    gevent.joinall([p1,])
    # # print(p1.value, p2.value)

    # p1 = Pool(processes=5)
    # res1=p1.apply_async(test, (9090,))
    # res_l.append(res1)
    # res2=p1.apply_async(test, (9091,))
    # res_l.append(res2)
    # p1.close()
    # p1.join()
    # for x in res_l:
    #     print(x.get())

    # print(result1.get())
