import subprocess
import logging


# Invokes a given command and returns the stdout
def invoke(command):
    logging.info('Try invoking')
    try:
        output = subprocess.check_output(command, shell=True,
                                  universal_newlines=True, stderr=subprocess.STDOUT)
        #err = output.communicate()
        logging.info( "\n\n\nError " + str(output))
    except Exception as e:
        logging.error("Failed to run %s" % (e))
    return output


# Invoke oc debug with command
def invoke_debug_helper(node_name, command):

    return invoke("oc debug node/" + node_name + " -- chroot /host;" + command + ";")

