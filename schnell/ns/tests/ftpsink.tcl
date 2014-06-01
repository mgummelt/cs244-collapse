Class Application/FTPSource -superclass Application

Class Application/FTPSink -superclass Application

Application/FTPSink instproc stopAt {nbytes what} {
    $self instvar bytesLeft
    $self instvar stopAction
    set bytesLeft $nbytes
    set stopAction $what
}

Application/FTPSink instproc recv { nbytes} {
    $self instvar bytesLeft
    $self instvar stopAction
    set bytesLeft [expr $bytesLeft - $nbytes]
    if { $bytesLeft <= 0 } {
        eval $stopAction
        set stopAction ""
    }
}

Class CountdownAction

CountdownAction instproc init {start_counter action_} {
    $self instvar count
    $self instvar action
    set count $start_counter
    set action $action_
}

CountdownAction instproc down {} {
    $self instvar count
    $self instvar action

    set count [expr $count - 1]
    if { $count == 0 } {
        eval $action
    }
}


