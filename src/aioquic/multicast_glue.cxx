/*
 * Copyright 2019, Akamai Technologies, Inc.
 * Jake Holland <jholland@akamai.com>
 * (MIT-licensed, please see LICENSE file in python-asyncio-taps for details)
 */

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <mcrx/libmcrx.h>

#define PY_SSIZE_T_CLEAN  /* Make "s#" use Py_ssize_t rather than int. */

#include <Python.h>

struct mc_glue_info {
  PyObject* py_obj;
  PyObject* add_sock_cb;
  PyObject* remove_sock_cb;
  int log_callbacks;
};
static PyObject *MCGlueError = NULL;

static PyObject*
mc_receive_packets(PyObject* dummy, PyObject* args) {
  long long ctx_val = 0;
  long long do_read_val = 0;
  long long handle_val = 0;
  int fd = 0;
  if (!PyArg_ParseTuple(args, "L|LLi", &ctx_val, &do_read_val,
        &handle_val, &fd)) {
    return NULL;
  }
  struct mcrx_ctx* ctx = (struct mcrx_ctx*)((intptr_t)ctx_val);
  if (!ctx) {
    PyErr_SetString(MCGlueError, "error: receive_packets with null ctx");
    return NULL;
  }
  int ret;
  if (do_read_val) {
    intptr_t handle = (intptr_t)handle_val;
    int (*do_receive)(intptr_t, int) =
      (int(*)(intptr_t, int))((intptr_t)do_read_val);
    ret = (*do_receive)(handle, fd);
    if (ret != MCRX_ERR_OK &&
        ret != MCRX_ERR_NOTHING_JOINED &&
        ret != MCRX_ERR_TIMEDOUT) {
      PyErr_SetString(MCGlueError, "error: unexpected error from do_receive callback");
      return NULL;
    }
  } else {
    ret = mcrx_ctx_receive_packets(ctx);
    if (ret != MCRX_ERR_OK &&
        ret != MCRX_ERR_NOTHING_JOINED &&
        ret != MCRX_ERR_TIMEDOUT) {
      PyErr_SetString(MCGlueError, "error: unexpected error from mcrx_ctx_receive_packets");
      return NULL;
    }
  }
  // TBD: do anything with the return value? (it's ignored by asyncio
  // loop.add_reader, that called this)
  Py_INCREF(Py_None);
  return Py_None;
}

static int mc_added_socket_cb(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*do_receive)(intptr_t handle, int fd)) {
  struct mc_glue_info* info = (struct mc_glue_info*)mcrx_ctx_get_userdata(ctx);

  PyObject* result = PyObject_CallFunction(info->add_sock_cb, "OLiL",
      info->py_obj,
      (long long)(intptr_t)(handle),
      fd,
      (long long)(intptr_t)do_receive);

  if (!result) {
    PyErr_SetString(MCGlueError, "OOM: no result from add_socket_cb");
    return MCRX_ERR_CALLBACK_FAILED;
  }
  Py_DECREF(result);

  // jake 2019-11-02:  insist on a do_receive call?  not sure if this
  // is needed. theoretically should be harmless, and could avoid some
  // trouble stacking up if the caller doesn't check it fast.
  do_receive(handle, fd);

  return MCRX_ERR_OK;
}

static int mc_removed_socket_cb(
    struct mcrx_ctx* ctx,
    int fd) {
  struct mc_glue_info* info = (struct mc_glue_info*)mcrx_ctx_get_userdata(ctx);

  PyObject* result = PyObject_CallFunction(info->remove_sock_cb,
      "Oi", info->py_obj, fd);
  if (!result) {
    PyErr_SetString(MCGlueError, "OOM: creating args for remove_socket_cb failed");
    return MCRX_ERR_CALLBACK_FAILED;
  }
  Py_DECREF(result);

  return MCRX_ERR_OK;
}

/*
 * args:
 * loop: the callback object passed with add_socket and remove_socket
 *       callbacks.
 *
 * returns: a ctx object, which later should be passed to
 * call_join
 */
static PyObject*
mc_initialize(PyObject* dummy, PyObject* args)
{
  int err;
  struct mcrx_ctx* ctx = NULL;
  err = mcrx_ctx_new(&ctx);
  if (!ctx) {
    PyErr_SetString(MCGlueError, "OOM: mcrx_ctx_new failed");
    return NULL;
  }
  struct mc_glue_info* info = (struct mc_glue_info*)calloc(sizeof(struct mc_glue_info), 1);
  if (!info) {
    PyErr_SetString(MCGlueError, "OOM: malloc of holder for mcrx_ctx failed");
    ctx = mcrx_ctx_unref(ctx);
    return NULL;
  }
  mcrx_ctx_set_userdata(ctx, (intptr_t)info);
  mcrx_ctx_set_log_priority(ctx, MCRX_LOGLEVEL_WARNING);

  if (!PyArg_ParseTuple(args, "O|OO", &info->py_obj, &info->add_sock_cb,
        &info->remove_sock_cb)) {
    ctx = mcrx_ctx_unref(ctx);
    free(info);
    return NULL;
  }

  PyObject* result = Py_BuildValue("L", (long long)(intptr_t)(ctx));
  if (!result) {
    ctx = mcrx_ctx_unref(ctx);
    free(info);
    return NULL;
  }

  if (info->add_sock_cb || info->remove_sock_cb) {
    if (!info->add_sock_cb || !info->remove_sock_cb) {
      PyErr_SetString(MCGlueError, "add/remove sock callbacks must be paired (both or neither)");
      ctx = mcrx_ctx_unref(ctx);
      free(info);
      Py_DECREF(result);
      return NULL;
    }
    if (!PyCallable_Check(info->add_sock_cb) ||
        !PyCallable_Check(info->remove_sock_cb)) {
      PyErr_SetString(MCGlueError, "add/remove sock callbacks must be callable");
      ctx = mcrx_ctx_unref(ctx);
      free(info);
      Py_DECREF(result);
      return NULL;
    }

    err = mcrx_ctx_set_receive_socket_handlers(ctx,
        mc_added_socket_cb, mc_removed_socket_cb);
    if (err != 0) {
      PyErr_SetString(MCGlueError, "internal error: add/remove sock callback setting failed");
      ctx = mcrx_ctx_unref(ctx);
      free(info);
      Py_DECREF(result);
      return NULL;
    }
    Py_INCREF(info->add_sock_cb);
    Py_INCREF(info->remove_sock_cb);
  }

  Py_INCREF(info->py_obj);

  return result;
}

static PyObject*
mc_cleanup(PyObject* dummy, PyObject* args)
{
  long long int ctx_val = 0;
  if (!PyArg_ParseTuple(args, "L", &ctx_val)) {
    return NULL;
  }
  struct mcrx_ctx* ctx = (struct mcrx_ctx*)((intptr_t)ctx_val);
  if (!ctx) {
    PyErr_SetString(MCGlueError, "error: cleanup with null ctx");
    return NULL;
  }
  struct mc_glue_info* info = (struct mc_glue_info*)mcrx_ctx_get_userdata(ctx);
  if (info) {
    if (info->add_sock_cb) {
      Py_DECREF(info->add_sock_cb);
    }
    if (info->remove_sock_cb) {
      Py_DECREF(info->remove_sock_cb);
    }
    if (info->py_obj) {
      Py_DECREF(info->py_obj);
    }
    mcrx_ctx_set_userdata(ctx, 0);
    free(info);
  }
  mcrx_ctx_unref(ctx);
  Py_INCREF(Py_None);
  return Py_None;
}

struct mc_glue_sub_info {
  int packets;
  //int (*got_data)(PyObject* conn, int len, uint8_t* data);
  PyObject* got_data;
  PyObject* conn;
};

static int mc_receive_cb(struct mcrx_packet* pkt) {
  mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct mc_glue_sub_info* info = (struct mc_glue_sub_info*)mcrx_subscription_get_userdata(sub);
  info->packets++;
  uint8_t* data = 0;
  int len = mcrx_packet_get_contents(pkt, &data);

  PyObject* data_obj = PyBytes_FromStringAndSize((const char*) data, len);
  if (!data_obj) {
    PyErr_SetString(MCGlueError, "OOM: creating bytes object for packet failed");
    mcrx_packet_unref(pkt);
    return MCRX_ERR_CALLBACK_FAILED;
  }

  uint16_t port = mcrx_packet_get_remote_port(pkt);
  PyObject* result = PyObject_CallFunction(info->got_data, "OiSi",
      info->conn, (Py_ssize_t)len, data_obj, port);
  if (!result) {
    PyErr_SetString(MCGlueError, "OOM: creating args for remove_socket_cb failed");
    mcrx_packet_unref(pkt);
    Py_DECREF(data_obj);
    return MCRX_ERR_CALLBACK_FAILED;
  }
  Py_DECREF(data_obj);
  Py_DECREF(result);

  mcrx_packet_unref(pkt);
  return MCRX_RECEIVE_CONTINUE;
}


static PyObject*
mc_join(PyObject* dummy, PyObject* args) {
  long long int ctx_val = 0;
  PyObject* conn = NULL;
  const char* source = NULL;
  const char* group = NULL;
  int port = 0;
  PyObject* got_data = NULL;

  if (!PyArg_ParseTuple(args, "LOssiO", &ctx_val, &conn, &source,
        &group, &port, &got_data)) {
    return NULL;
  }
  struct mcrx_ctx* ctx = (struct mcrx_ctx*)((intptr_t)ctx_val);
  if (!ctx) {
    PyErr_SetString(MCGlueError, "error: join with null ctx");
    return NULL;
  }
  if (!PyCallable_Check(got_data)) {
      PyErr_SetString(MCGlueError, "got_data callbacks must be callable");
      return NULL;
  }

  int err = 0;
  struct mcrx_subscription_config cfg = MCRX_SUBSCRIPTION_CONFIG_INIT;
  err = mcrx_subscription_config_pton(&cfg, source, group);
  if (err != 0) {
    PyErr_SetString(MCGlueError, "error configuring (S,G)");
    return NULL;
  }
  cfg.port = port;

  struct mcrx_subscription* sub = 0;
  err = mcrx_subscription_new(ctx, &cfg, &sub);
  if (err != 0) {
    PyErr_SetString(MCGlueError, "error creating subscription (S,G):P");
    return NULL;
  }

  struct mc_glue_sub_info* subinfo = (struct mc_glue_sub_info*)calloc(sizeof(struct mc_glue_sub_info), 1);
  if (!subinfo) {
    mcrx_subscription_unref(sub);
    PyErr_SetString(MCGlueError, "OOM: failed alloc of sub_info");
    return NULL;
  }

  Py_INCREF(conn);
  Py_INCREF(got_data);
  subinfo->conn = conn;
  subinfo->got_data = got_data;

  mcrx_subscription_set_receive_cb(sub, mc_receive_cb);
  mcrx_subscription_set_userdata(sub, (intptr_t)subinfo);

  err = mcrx_subscription_join(sub);
  if (err != 0) {
    mcrx_subscription_unref(sub);
    free(subinfo);
    PyErr_SetString(MCGlueError, "error joining (S,G):P");
    return NULL;
  }

  PyObject* result = Py_BuildValue("L", (long long)(intptr_t)(sub));
  if (!result) {
    mcrx_subscription_unref(sub);
    free(subinfo);
    return NULL;
  }

  return result;
}

static PyObject*
mc_leave(PyObject* dummy, PyObject* args) {
  long long int sub_val = 0;

  if (!PyArg_ParseTuple(args, "L", &sub_val)) {
    return NULL;
  }
  struct mcrx_subscription* sub = (struct mcrx_subscription*)sub_val;
  struct mc_glue_sub_info* info = (struct mc_glue_sub_info*)mcrx_subscription_get_userdata(sub);
  mcrx_subscription_set_userdata(sub, (intptr_t)0);

  if (info) {
    if (info->conn) {
      Py_DECREF(info->conn);
    }
    if (info->got_data) {
      Py_DECREF(info->got_data);
    }
    free(info);
  }

  int err = mcrx_subscription_leave(sub);
  // if there was a problem, it probably printed something.  ignore?
  (void)err;
  sub = mcrx_subscription_unref(sub);

  Py_INCREF(Py_None);
  return Py_None;
}


static const char* glue_doc = "python multicast_glue module wrapper around libmcrx (https://github.com/GrumpyOldTroll/libmcrx)";

static PyMethodDef MCGlueMethods[] = {
    {"initialize",  mc_initialize, METH_VARARGS,
     "initialize(py_obj, add_sock_cb?, rem_sock_cb?): returns a ctx, a handle for future calls.\n  add_sock_cb(py_obj, handle, fd, do_read): callback when socket is created:\n.      When fd is read-ready, receive_packets(ctx, do_read, handle, fd) should be called.\n  remove_sock_cb(py_obj, fd): callback when socket is removed.\n(both or neither of add/remove_sock_cb should be passed)"},
    {"cleanup",  mc_cleanup, METH_VARARGS,
     "cleanup(ctx): cleans up a multicast context returned from initialize."},
    {"receive_packets",  mc_receive_packets, METH_VARARGS,
     "receive_packets(ctx): Receive callbacks from the join happen during this call.\n  If sockets are externally managed, this should be called whenever data is ready to read, else should be called in a loop on a thread, and will block for 1s+rand(1s)."},
    {"join",  mc_join, METH_VARARGS,
     "join(ctx, py_sub_obj, src_ip, grp_ip, prt, receive_cb): joins channel, calls receive_cb(py_sub_obj, len, bytes) for each packet received, during receive_packets.  Returns a sub_ctx for the subscription."},
    {"leave", mc_leave, METH_VARARGS, "leave(sub_ctx): unsubscribes"},
    {NULL, NULL, 0, NULL}
};

// https://docs.python.org/3/c-api/module.html
static struct PyModuleDef mcgluemodule = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "multicast_glue",
    .m_doc = glue_doc,
    .m_size = sizeof(PyObject) + 2*sizeof(PyObject*),
    .m_methods = MCGlueMethods
    // .m_slots = NULL,
    // .m_reload = NULL,
    // .m_clear = NULL,
    // .m_free = NULL
};

PyMODINIT_FUNC
PyInit_multicast_glue(void)
{
  PyObject *m;

  m = PyModule_Create(&mcgluemodule);
  if (m == NULL)
      return NULL;

  MCGlueError = PyErr_NewException("multicast_glue.error", NULL, NULL);
  Py_XINCREF(MCGlueError);
  if (PyModule_AddObject(m, "error", MCGlueError) < 0) {
      Py_XDECREF(MCGlueError);
      Py_CLEAR(MCGlueError);
      Py_DECREF(m);
      return NULL;
  }

  return m;
}
