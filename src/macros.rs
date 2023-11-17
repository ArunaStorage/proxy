#[macro_export]
macro_rules! required {
    ($option:expr) => {
        match $option {
            Some(value) => value,
            None => return Err(tonic::Status::invalid_argument("Missing required field")),
        }
    };
}

#[macro_export]
macro_rules! trace_err {
    ($request:expr) => {
        $request.map_err(|e| {
            tracing::error!(error = ?e, msg = e.to_string());
            e
        })
    };
}