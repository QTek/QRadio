import subprocess


def get_qradio_data(command, result_column = 0 ):
    python_path = 'C:\Python27\python.exe'
    qradio_path = 'C:\MaltegoTransforms\QRadio\cli_qradio.py'
    error = "lol"
    output = []

    command_final = python_path + ' ' + qradio_path + ' ' + command
    p = subprocess.Popen(command_final, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    try:
        result = out.split('\n')
        del result[0]
    except:
        error = "yay..."

    for lin in result:
        try:
            final_out = lin.split(',')[result_column].strip("\n").strip("\r")
            if final_out != "" and final_out != " ":
                output.append(final_out)
        except:
            error = 'oh no...'
    return output
