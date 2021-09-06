# Terraform module which creates ECS Scheduled Task resources on AWS.
locals {
  ecs_task_execution_iam_name = "${var.name}-ecs-task-execution"
  enabled_ecs_task_execution  = var.enabled && var.create_ecs_task_execution_role ? 1 : 0
}

resource "aws_cloudwatch_event_rule" "default" {
  count               = var.enabled ? 1 : 0
  name                = var.name
  description         = var.description
  is_enabled          = var.is_enabled
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "default" {
  count     = var.enabled ? 1 : 0
  target_id = var.name
  arn       = var.cluster_arn
  rule      = aws_cloudwatch_event_rule.default[0].name
  role_arn  = var.create_ecs_events_role ? join("", aws_iam_role.ecs_events.*.arn) : var.ecs_events_role_arn

  ecs_target {
    launch_type         = "FARGATE"
    task_count          = var.task_count
    task_definition_arn = aws_ecs_task_definition.default[0].arn
    platform_version    = var.platform_version

    network_configuration {
      assign_public_ip = var.assign_public_ip
      security_groups  = var.security_groups
      subnets          = var.subnets
    }
  }
}

resource "aws_iam_role" "ecs_events" {
  count              = local.enabled_ecs_events
  name               = local.ecs_events_iam_name
  assume_role_policy = data.aws_iam_policy_document.ecs_events_assume_role_policy.json
  path               = var.iam_path
  description        = var.description
  tags               = merge({ "Name" = local.ecs_events_iam_name }, var.tags)
}

data "aws_iam_policy_document" "ecs_events_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "ecs_events" {
  count       = local.enabled_ecs_events
  name        = local.ecs_events_iam_name
  policy      = data.aws_iam_policy.ecs_events.policy
  path        = var.iam_path
  description = var.description
}

data "aws_iam_policy" "ecs_events" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceEventsRole"
}

resource "aws_iam_role_policy_attachment" "ecs_events" {
  count      = local.enabled_ecs_events
  role       = aws_iam_role.ecs_events[0].name
  policy_arn = aws_iam_policy.ecs_events[0].arn
}

locals {
  ecs_events_iam_name = "${var.name}-ecs-events"
  enabled_ecs_events  = var.enabled && var.create_ecs_events_role ? 1 : 0
}

resource "aws_ecs_task_definition" "default" {
  count                    = var.enabled ? 1 : 0
  family                   = var.name
  execution_role_arn       = var.create_ecs_task_execution_role ? join("", aws_iam_role.ecs_task_execution.*.arn) : var.ecs_task_execution_role_arn
  task_role_arn            = var.task_role_arn
  container_definitions    = var.container_definitions
  cpu                      = var.cpu
  memory                   = var.memory
  requires_compatibilities = var.requires_compatibilities
  network_mode             = "awsvpc"
  tags                     = merge({ "Name" = var.name }, var.tags)
}

resource "aws_iam_role" "ecs_task_execution" {
  count              = local.enabled_ecs_task_execution
  name               = local.ecs_task_execution_iam_name
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role_policy.json
  path               = var.iam_path
  description        = var.description
  tags               = merge({ "Name" = local.ecs_task_execution_iam_name }, var.tags)
}

data "aws_iam_policy_document" "ecs_task_execution_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "ecs_task_execution" {
  count       = local.enabled_ecs_task_execution
  name        = local.ecs_task_execution_iam_name
  policy      = data.aws_iam_policy.ecs_task_execution.policy
  path        = var.iam_path
  description = var.description
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  count      = local.enabled_ecs_task_execution
  role       = aws_iam_role.ecs_task_execution[0].name
  policy_arn = aws_iam_policy.ecs_task_execution[0].arn
}

data "aws_iam_policy" "ecs_task_execution" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
