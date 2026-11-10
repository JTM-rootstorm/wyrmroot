//! The shell's inspection commands: services, tasks and status.

use super::*;

pub(crate) fn inspect_services<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
) -> Result<(), ShellError> {
    let transaction = match transactions.registry() {
        Ok(value) => value,
        Err(error) => {
            return inspection_failure(system, stderr, stdout, controls, "services", error);
        }
    };
    let mut request = [0_u8; wyrmroot_registry_proto::HEADER_BYTES];
    let size = inspection::encode_registry_request(identity, transaction, &mut request)
        .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    if let Err(error) = send_control(
        system,
        controls.registry,
        EndpointRole::Registry,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    ) {
        return control_transport_failure(system, stderr, stdout, controls, "services", error);
    }

    let mut sequence = RegistrySequence::new();
    loop {
        let mut response = [0_u8; REGISTRY_REPLY_BYTES];
        let used = match receive_control(
            system,
            controls.registry,
            EndpointRole::Registry,
            controls,
            stdout.endpoint().handle(),
            stderr.endpoint().handle(),
            &mut response,
            deadline,
        ) {
            Ok(value) => value,
            Err(error) => {
                return control_transport_failure(
                    system, stderr, stdout, controls, "services", error,
                );
            }
        };
        match sequence.accept(identity, transaction, &response[..used], 0) {
            Ok(complete) => {
                if let Err(error) = ensure_before_control_deadline(system, deadline) {
                    return control_transport_failure(
                        system, stderr, stdout, controls, "services", error,
                    );
                }
                if complete {
                    break;
                }
            }
            Err(error) => {
                return inspection_failure(system, stderr, stdout, controls, "services", error);
            }
        }
    }

    if sequence.len() == 0 {
        return write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b"services: empty\n",
        );
    }
    for index in 0..sequence.len() {
        let record = sequence
            .record(index)
            .ok_or(ShellError::InspectionProtocol)?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b"service name=",
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            record.name(),
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" protocol=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            record.protocol_id,
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" versions=",
        )?;
        for version_index in 0..usize::from(record.version_count) {
            if version_index != 0 {
                write_stdout(system, stdout, stderr.endpoint().handle(), controls, b",")?;
            }
            let version = record.versions[version_index];
            write_u64(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                u64::from(version.major),
            )?;
            write_stdout(system, stdout, stderr.endpoint().handle(), controls, b".")?;
            write_u64(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                u64::from(version.minor),
            )?;
        }
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" generation=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            record.service_generation,
        )?;
        write_stdout(system, stdout, stderr.endpoint().handle(), controls, b"\n")?;
    }
    Ok(())
}

pub(crate) fn inspect_tasks<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
) -> Result<(), ShellError> {
    let transaction = match transactions.launch() {
        Ok(value) => value,
        Err(error) => return inspection_failure(system, stderr, stdout, controls, "tasks", error),
    };
    let mut request = [0_u8; wyrmroot_launch_proto::HEADER_BYTES];
    let size = inspection::encode_launch_request(identity, transaction, &mut request)
        .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    if let Err(error) = send_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    ) {
        return control_transport_failure(system, stderr, stdout, controls, "tasks", error);
    }
    let mut response = [0_u8; JOB_REPLY_BYTES];
    let used = match receive_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &mut response,
        deadline,
    ) {
        Ok(value) => value,
        Err(error) => {
            return control_transport_failure(system, stderr, stdout, controls, "tasks", error);
        }
    };
    let jobs = match inspection::decode_jobs(identity, transaction, &response[..used], 0) {
        Ok(value) => value,
        Err(error) => return inspection_failure(system, stderr, stdout, controls, "tasks", error),
    };
    if let Err(error) = ensure_before_control_deadline(system, deadline) {
        return control_transport_failure(system, stderr, stdout, controls, "tasks", error);
    }
    if jobs.is_empty() {
        return write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b"tasks: empty\n",
        );
    }
    for index in 0..jobs.len() {
        let job = jobs.get(index).ok_or(ShellError::InspectionProtocol)?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b"task job=",
        )?;
        write_u64(system, stdout, stderr.endpoint().handle(), controls, job)?;
        // LIST_JOBS membership means active and visible to this exact ShellJobs
        // connection. It does not distinguish Running from Terminating.
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" state=active\n",
        )?;
    }
    Ok(())
}

pub(crate) fn inspect_status<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
) -> Result<(), ShellError> {
    let transaction = match transactions.status() {
        Ok(value) => value,
        Err(error) => return inspection_failure(system, stderr, stdout, controls, "status", error),
    };
    let deadline = control_deadline(system)?;
    let mut request = [0_u8; wyrmroot_console_proto::HEADER_BYTES];
    let size = inspection::encode_status_request(identity, transaction, &mut request)
        .map_err(|_| ShellError::InspectionProtocol)?;
    if let Err(error) = send_control(
        system,
        controls.console_status,
        EndpointRole::ConsoleStatus,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    ) {
        return control_transport_failure(system, stderr, stdout, controls, "status", error);
    }
    let mut response = [0_u8; wyrmroot_console_proto::MAX_MESSAGE_BYTES];
    let used = match receive_control(
        system,
        controls.console_status,
        EndpointRole::ConsoleStatus,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &mut response,
        deadline,
    ) {
        Ok(value) => value,
        Err(error) => {
            return control_transport_failure(system, stderr, stdout, controls, "status", error);
        }
    };
    let snapshot = match inspection::decode_status(identity, transaction, &response[..used], 0) {
        Ok(value) => value,
        Err(error) => return inspection_failure(system, stderr, stdout, controls, "status", error),
    };
    if let Err(error) = ensure_before_control_deadline(system, deadline) {
        return control_transport_failure(system, stderr, stdout, controls, "status", error);
    }

    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b"status state=",
    )?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        status_state_name(snapshot.state),
    )?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" shell-generation=",
    )?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        identity.child_generation,
    )?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" endpoints=healthy flags=",
    )?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        u64::from(snapshot.flags),
    )?;
    if snapshot.flags & wyrmroot_console_proto::FLAG_SERIAL_PRESENT != 0 {
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" registry-generation=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.serial_registry_generation,
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" serial-generation=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.raw_stream_generation,
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" publication-generation=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.publication_generation,
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" driver-attempt=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.driver_attempt,
        )?;
    }
    if snapshot.flags & wyrmroot_console_proto::FLAG_CHILD_PRESENT != 0 {
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" child-generation=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.child_generation,
        )?;
        write_stdout(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            b" outer-job=",
        )?;
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            snapshot.outer_job,
        )?;
    }
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" peers=",
    )?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        u64::from(snapshot.live_peer_mask),
    )?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" queues=",
    )?;
    for (index, value) in [
        snapshot.input_queue_bytes,
        snapshot.stdout_queue_bytes,
        snapshot.stderr_queue_bytes,
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            write_stdout(system, stdout, stderr.endpoint().handle(), controls, b",")?;
        }
        write_u64(
            system,
            stdout,
            stderr.endpoint().handle(),
            controls,
            u64::from(value),
        )?;
    }
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" failures=",
    )?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        u64::from(snapshot.child_failures),
    )?;
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, b",")?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        u64::from(snapshot.serial_failures),
    )?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" last=",
    )?;
    write_u64(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        snapshot.last_failure as u64,
    )?;
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, b"\n")
}

pub(crate) fn inspection_failure<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &str,
    error: InspectionError,
) -> Result<(), ShellError> {
    match error {
        InspectionError::Registry(_) | InspectionError::Launch(_) | InspectionError::Console(_) => {
            write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                b"unavailable: ",
            )?;
            write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                command.as_bytes(),
            )?;
            write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")?;
            Err(ShellError::InspectionProtocol)
        }
        InspectionError::CounterOverflow => Err(ShellError::TransactionExhausted),
        InspectionError::Encode
        | InspectionError::Malformed
        | InspectionError::Correlation
        | InspectionError::Sequence => Err(ShellError::InspectionProtocol),
    }
}

pub(crate) fn control_transport_failure<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &str,
    error: ShellError,
) -> Result<(), ShellError> {
    if !matches!(error, ShellError::InspectionTimeout) {
        return Err(error);
    }
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b"unavailable: ",
    )?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        command.as_bytes(),
    )?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")?;
    Err(ShellError::InspectionTimeout)
}
