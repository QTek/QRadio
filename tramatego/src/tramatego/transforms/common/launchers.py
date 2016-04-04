import subprocess


def get_qradio_data(command, result_column = 0 ):
    python_path = 'python'
    qradio_path = 'path_to_cli_qradio.py'

    command_final = python_path + " " + qradio_path + ' ' + command
    p = subprocess.Popen(command_final, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    result = out.split('\n')
    output = []
    for lin in result:
        if not lin.startswith('#'):
			try:
				final_out = lin.split(',')[result_column]
				output.append(final_out)
			except:
				output.append("Error in Transform")
    return output