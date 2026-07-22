from app.routers.mikrotik import api


class MayaActions:

    # -----------------------------
    # PPP
    # -----------------------------

    @staticmethod
    def disconnect_pppoe(router, username):

        conn = api(router)

        for session in conn.path("ppp", "active"):

            if session.get("name") == username:

                conn.path(
                    "ppp",
                    "active"
                ).remove(session[".id"])

                return True

        return False

    # -----------------------------
    # Queue
    # -----------------------------

    @staticmethod
    def disable_queue(router, queue_name):

        conn = api(router)

        for queue in conn.path("queue", "simple"):

            if queue.get("name") == queue_name:

                conn.path(
                    "queue",
                    "simple"
                ).set(

                    id=queue[".id"],

                    disabled="yes"

                )

                return True

        return False

    @staticmethod
    def enable_queue(router, queue_name):

        conn = api(router)

        for queue in conn.path("queue", "simple"):

            if queue.get("name") == queue_name:

                conn.path(
                    "queue",
                    "simple"
                ).set(

                    id=queue[".id"],

                    disabled="no"

                )

                return True

        return False

    # -----------------------------
    # Interface
    # -----------------------------

    @staticmethod
    def disable_interface(router, interface):

        conn = api(router)

        for iface in conn.path("interface"):

            if iface.get("name") == interface:

                conn.path("interface").set(

                    id=iface[".id"],

                    disabled="yes"

                )

                return True

        return False

    @staticmethod
    def enable_interface(router, interface):

        conn = api(router)

        for iface in conn.path("interface"):

            if iface.get("name") == interface:

                conn.path("interface").set(

                    id=iface[".id"],

                    disabled="no"

                )

                return True

        return False
