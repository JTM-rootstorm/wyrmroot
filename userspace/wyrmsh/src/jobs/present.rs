//! Closing jobs and presenting results and errors.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn close_job<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    job_id: u64,
) -> Result<(), ShellError> {
    match fixed_job_request(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        MessageType::CloseJob,
        job_id,
    )? {
        Reply::Closed(actual) if actual == job_id => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            Ok(())
        }
        Reply::Error(ErrorCode::ForeignOrUnknownJob) => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            Ok(())
        }
        Reply::Error(code) => {
            expected_operation_error(system, stderr, stdout, controls, b"close", code)
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fixed_job_request<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    kind: MessageType,
    value: u64,
) -> Result<Reply, ShellError> {
    let transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, transaction),
        kind,
        value,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    send_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    )?;
    let mut response = [0_u8; 88];
    let used = receive_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &mut response,
        deadline,
    )?;
    let reply = decode_reply(identity, transaction, &response[..used], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    ensure_before_control_deadline(system, deadline)?;
    Ok(reply)
}

pub(crate) fn present_result<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &NativeOutput,
    controls: Controls,
    job_id: u64,
    result: TerminationResult,
    suffix: Option<&[u8]>,
) -> Result<(), ShellError> {
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b"job result job=",
    )?;
    write_decimal(system, stdout, stderr, controls, job_id)?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" classification=",
    )?;
    let class = match result.classification {
        TerminationClassification::NormalExit => b"normal".as_slice(),
        TerminationClassification::Authorized => b"authorized".as_slice(),
        TerminationClassification::UnhandledException => b"exception".as_slice(),
        TerminationClassification::ResourcePolicy => b"resource-policy".as_slice(),
        TerminationClassification::TaskGroupTeardown => b"task-group-teardown".as_slice(),
    };
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, class)?;
    for (label, value) in [
        (
            b" application=".as_slice(),
            u64::from(result.application_code),
        ),
        (
            b" exception-class=".as_slice(),
            u64::from(result.exception_class),
        ),
        (
            b" exception-detail=".as_slice(),
            u64::from(result.exception_detail),
        ),
        (b" exception-address=".as_slice(), result.exception_address),
        (b" cleanup=".as_slice(), u64::from(result.cleanup_result)),
    ] {
        write_stdout(system, stdout, stderr.endpoint().handle(), controls, label)?;
        write_decimal(system, stdout, stderr, controls, value)?;
    }
    if let Some(suffix) = suffix {
        write_stdout(system, stdout, stderr.endpoint().handle(), controls, suffix)?;
    }
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, b"\n")
}

pub(crate) fn write_decimal<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &NativeOutput,
    controls: Controls,
    mut value: u64,
) -> Result<(), ShellError> {
    let mut bytes = [0_u8; 20];
    let mut cursor = bytes.len();
    loop {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return write_stdout(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                &bytes[cursor..],
            );
        }
    }
}

pub(crate) fn launch_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    code: ErrorCode,
) -> Result<(), ShellError> {
    if !recoverable_launch_error(code) {
        return Err(ShellError::InspectionProtocol);
    }
    expected_text(system, stderr, stdout, controls, command, error_name(code))
}

pub(crate) fn expected_operation_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    code: ErrorCode,
) -> Result<(), ShellError> {
    match code {
        ErrorCode::ForeignOrUnknownJob | ErrorCode::InvalidState => {
            expected_text(system, stderr, stdout, controls, command, error_name(code))
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

pub(crate) fn error_name(code: ErrorCode) -> &'static [u8] {
    match code {
        ErrorCode::MalformedRequest => b"malformed",
        ErrorCode::StaleOrUnknownSession => b"stale-session",
        ErrorCode::TransactionReplay => b"transaction-replay",
        ErrorCode::ForeignOrUnknownJob => b"foreign",
        ErrorCode::InvalidState => b"invalid-state",
        ErrorCode::Capacity => b"capacity",
        ErrorCode::PolicyRejected => b"policy-rejected",
        ErrorCode::LoaderFailure => b"loader-failure",
        ErrorCode::CleanupFailure => b"cleanup-failure",
        ErrorCode::CancellationUnavailable => b"cancellation-unavailable",
    }
}

pub(crate) fn expected_text<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    status: &[u8],
) -> Result<(), ShellError> {
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        command,
    )?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" status=",
    )?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, status)?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")
}

pub(crate) fn expected_job_text<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    job_id: u64,
    status: &[u8],
) -> Result<(), ShellError> {
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        command,
    )?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" job=",
    )?;
    write_decimal_stderr(system, stderr, stdout, controls, job_id)?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" status=",
    )?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, status)?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")
}

pub(crate) fn write_decimal_stderr<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    mut value: u64,
) -> Result<(), ShellError> {
    let mut bytes = [0_u8; 20];
    let mut cursor = bytes.len();
    loop {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                &bytes[cursor..],
            );
        }
    }
}
