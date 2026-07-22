from app.ai.remediation import MayaRemediation
from app.ai.actions import MayaActions


class MayaExecutor:
    """
    Executes approved remediation plans.

    Safety Rules:
    ----------------
    1. Nothing is executed unless approve=True
    2. Every action returns success/failure
    3. Execution report is returned
    """

    @staticmethod
    def execute(
        router: str,
        approve: bool = False,
        action: str = None,
        target: str = None
    ):

        plan = MayaRemediation.plan(router)

        # ---------------------------------------
        # Approval Required
        # ---------------------------------------

        if not approve:

            return {

                "status": "awaiting_approval",

                "router": router,

                "root_cause": plan["root_cause"],

                "confidence": plan["confidence"],

                "recommended_plan": plan["plan"],

                "message":
                    "Execution requires approval."

            }

        executed = []

        failed = []

        # ---------------------------------------
        # Execute Specific Action
        # ---------------------------------------

        if action == "disconnect_pppoe":

            if MayaActions.disconnect_pppoe(router, target):

                executed.append(

                    f"Disconnected PPPoE user '{target}'."

                )

            else:

                failed.append(

                    f"Failed to disconnect '{target}'."

                )

        elif action == "disable_queue":

            if MayaActions.disable_queue(router, target):

                executed.append(

                    f"Queue '{target}' disabled."

                )

            else:

                failed.append(

                    f"Queue '{target}' not found."

                )

        elif action == "enable_queue":

            if MayaActions.enable_queue(router, target):

                executed.append(

                    f"Queue '{target}' enabled."

                )

            else:

                failed.append(

                    f"Queue '{target}' not found."

                )

        elif action == "disable_interface":

            if MayaActions.disable_interface(router, target):

                executed.append(

                    f"Interface '{target}' disabled."

                )

            else:

                failed.append(

                    f"Interface '{target}' not found."

                )

        elif action == "enable_interface":

            if MayaActions.enable_interface(router, target):

                executed.append(

                    f"Interface '{target}' enabled."

                )

            else:

                failed.append(

                    f"Interface '{target}' not found."

                )

        elif action is None:

            executed.append(

                "No executable action supplied. Returning remediation plan."

            )

        else:

            failed.append(

                f"Unknown action '{action}'."

            )

        # ---------------------------------------
        # Final Report
        # ---------------------------------------

        return {

            "status": "completed" if len(failed) == 0 else "completed_with_errors",

            "router": router,

            "root_cause": plan["root_cause"],

            "confidence": plan["confidence"],

            "executed": executed,

            "failed": failed,

            "recommended_plan": plan["plan"]

        }
