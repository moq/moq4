// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

using Moq.Properties;

using TypeNameFormatter;

namespace Moq
{
	[DebuggerStepThrough]
	internal static class Guard
	{
		public static void CanCreateInstance(Type type)
		{
			if (!type.CanCreateInstance())
			{
				throw new ArgumentException(
					string.Format(
						CultureInfo.CurrentCulture,
						Resources.TypeHasNoDefaultConstructor,
						type.GetFormattedName()));
			}
		}

		public static void ImplementsInterface(Type interfaceType, Type type, string paramName = null)
		{
			Debug.Assert(interfaceType != null);
			Debug.Assert(interfaceType.IsInterface);

			Debug.Assert(type != null);

			if (interfaceType.IsAssignableFrom(type) == false)
			{
				throw new ArgumentException(
					string.Format(
						CultureInfo.CurrentCulture,
						Resources.TypeNotImplementInterface,
						type.GetFormattedName(),
						interfaceType.GetFormattedName()),
					paramName);
			}
		}

		public static void ImplementsTypeMatcherProtocol(Type type)
		{
			Debug.Assert(type != null);

			Guard.ImplementsInterface(typeof(ITypeMatcher), type);
			Guard.CanCreateInstance(type);
		}

		public static void IsAssignmentToPropertyOrIndexer(LambdaExpression expression, string paramName)
		{
			Debug.Assert(expression != null);

			switch (expression.Body.NodeType)
			{
				case ExpressionType.Assign:
					var assignment = (BinaryExpression)expression.Body;
					if (assignment.Left is MemberExpression || assignment.Left is IndexExpression) return;
					break;

				case ExpressionType.Call:
					var call = (MethodCallExpression)expression.Body;
					if (call.Method.IsSetAccessor()) return;
					break;
			}

			throw new ArgumentException(
				string.Format(
					CultureInfo.CurrentCulture,
					Resources.SetupNotSetter,
					expression.ToStringFixed()),
				paramName);
		}

		public static void IsOverridable(MethodInfo method, Expression expression)
		{
			if (method.IsStatic)
			{
				throw new NotSupportedException(
					string.Format(
						CultureInfo.CurrentCulture,
						Resources.UnsupportedExpressionWithHint,
						expression.ToStringFixed(),
						string.Format(
							CultureInfo.CurrentCulture,
							method.IsExtensionMethod() ? Resources.UnsupportedExtensionMethod : Resources.UnsupportedStaticMember,
							$"{method.DeclaringType.GetFormattedName()}.{method.Name}")));
			}
			else if (!method.CanOverride())
			{
				throw new NotSupportedException(
					string.Format(
						CultureInfo.CurrentCulture,
						Resources.UnsupportedExpressionWithHint,
						expression.ToStringFixed(),
						string.Format(
							CultureInfo.CurrentCulture,
							Resources.UnsupportedNonOverridableMember,
							$"{method.DeclaringType.GetFormattedName()}.{method.Name}")));
			}
		}

		public static void IsVisibleToProxyFactory(MethodInfo method)
		{
			if (ProxyFactory.Instance.IsMethodVisible(method, out string messageIfNotVisible) == false)
			{
				throw new ArgumentException(string.Format(
					CultureInfo.CurrentCulture,
					Resources.MethodNotVisibleToProxyFactory,
					method.DeclaringType.Name,
					method.Name,
					messageIfNotVisible));
			}
		}

		public static void IsEventAdd(LambdaExpression expression, string paramName)
		{
			Debug.Assert(expression != null);

			switch (expression.Body.NodeType)
			{
				case ExpressionType.Call:
					var call = (MethodCallExpression)expression.Body;
					if (call.Method.IsEventAddAccessor()) return;
					break;
			}

			throw new ArgumentException(
				string.Format(
					CultureInfo.CurrentCulture,
					Resources.SetupNotEventAdd,
					expression.ToStringFixed()),
				paramName);
		}

		public static void IsEventRemove(LambdaExpression expression, string paramName)
		{
			Debug.Assert(expression != null);

			switch (expression.Body.NodeType)
			{
				case ExpressionType.Call:
					var call = (MethodCallExpression)expression.Body;
					if (call.Method.IsEventRemoveAccessor()) return;
					break;
			}

			throw new ArgumentException(
				string.Format(
					CultureInfo.CurrentCulture,
					Resources.SetupNotEventRemove,
					expression.ToStringFixed()),
				paramName);
		}

		/// <summary>
		/// Ensures the given <paramref name="value"/> is not null.
		/// Throws <see cref="ArgumentNullException"/> otherwise.
		/// </summary>
		public static void NotNull(object value, string paramName)
		{
			if (value == null)
			{
				throw new ArgumentNullException(paramName);
			}
		}

		/// <summary>
		/// Ensures the given string <paramref name="value"/> is not null or empty.
		/// Throws <see cref="ArgumentNullException"/> in the first case, or 
		/// <see cref="ArgumentException"/> in the latter.
		/// </summary>
		public static void NotNullOrEmpty(string value, string paramName)
		{
			if (value == null)
			{
				throw new ArgumentNullException(paramName);
			}

			if (value.Length == 0)
			{
				throw new ArgumentException(Resources.ArgumentCannotBeEmpty, paramName);
			}
		}

		public static void NotField(MemberExpression memberAccess)
		{
			if (memberAccess.Member is FieldInfo)
				throw new NotSupportedException(
					string.Format(
						Resources.FieldsNotSupported,
						memberAccess.ToStringFixed()));
		}

		public static void IsMockable(Type type)
		{
			if (!type.IsMockable())
			{
				throw new NotSupportedException(
					string.Format(
						Resources.TypeNotMockable,
						type.GetFormattedName()));
			}
		}

		public static void Positive(TimeSpan delay)
		{
			if (delay <= TimeSpan.Zero)
			{
				throw new ArgumentException(Resources.DelaysMustBeGreaterThanZero);
			}
		}

		public static void CanRead(PropertyInfo property)
		{
			if (!property.CanRead(out _))
			{
				throw new ArgumentException(string.Format(
					CultureInfo.CurrentCulture,
					Resources.PropertyGetNotFound,
					property.DeclaringType.Name, property.Name));
			}
		}

		public static void CanWrite(PropertyInfo property)
		{
			if (!property.CanWrite(out _))
			{
				throw new ArgumentException(string.Format(
					CultureInfo.CurrentCulture,
					Resources.PropertySetNotFound,
					property.DeclaringType.Name, property.Name));
			}
		}

		public static void IsIndexerGetter(LambdaExpression expression,string paramName)
		{
			if (expression.Body is MethodCallExpression methodCall)
			{
				var method = methodCall.Method;
				var isGetAccessor = method.IsGetAccessor();
				var isIndexerAccessor = method.IsIndexerAccessor();
				if (isGetAccessor && isIndexerAccessor)
				{
					return;
				}
			}

			throw new ArgumentException(
				string.Format(
					CultureInfo.CurrentCulture,
					Resources.SetupNotIndexerGetter,
					expression.ToStringFixed()),
				paramName);

		}

		public static void AreConstantExpressions(IEnumerable<Expression> expressions,string paramName)
		{
			var notConstantExpression = expressions.FirstOrDefault(arg => !(arg is ConstantExpression));
			if(notConstantExpression != null)
			{
				throw new ArgumentException(
				string.Format(
					CultureInfo.CurrentCulture,
					Resources.ArgumentsNotConstantExpressions,
					notConstantExpression.ToStringFixed()),
				paramName);
			}
			
		}
	}
}
