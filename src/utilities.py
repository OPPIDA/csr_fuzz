#------------------------------------------
#
#  Utility functions
#
#------------------------------------------

def red(s):
	return "\033[31m%s\033[0m" % s

def green(s):
	return "\033[32m%s\033[0m" % s

def yellow(s):
	return "\033[93m%s\033[0m" % s

def cyan(s):
	return "\033[36m%s\033[0m" % s	

def info(s):
	print("[%s] %s" % (cyan("info"), s))

def success(s):
	print("[%s] %s" % (green("success"), s))

def error(s):
	print("[%s] %s" % (red("error"), s))

def warning(s):
	print("[%s] %s" % (yellow("warning"), s))