package io.trino.spi.security.SystemAccessControl


#test suite for validating configuration

test_user_suite_true{
	count(user_suite_true) == count(valid) with input.pass as true
}

test_user_suite_false{
	count(valid)==0 with input.pass as false
}

valid[oks]{
    checkCanImpersonateUser with input as user_suite_true[i]
	oks = user_suite_true[i]
    trace(sprintf("oks %v",[oks]))
}

user_suite_true[suites]{
    suites = data.testsuites.user.cases[i].input
  	data.testsuites.user.cases[i].result = input.pass
  	trace(sprintf("suites %v",[suites]))
}
