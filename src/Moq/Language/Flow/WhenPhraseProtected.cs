// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using Moq.Properties;
using Moq.Protected;

namespace Moq.Language.Flow
{
	internal sealed class WhenPhraseProtected<T,TAnalog> : ISetupConditionResultProtected<T,TAnalog>
		where T : class
		where TAnalog : class
	{
		private static DuckReplacer DuckReplacerInstance = new DuckReplacer(typeof(TAnalog), typeof(T));

		private Mock<T> mock;
		private Condition condition;

		public WhenPhraseProtected(IProtectedAsMock<T, TAnalog> protectedAsMock, Condition condition)
		{
			mock = protectedAsMock.Mocked;
			this.condition = condition;
		}

		public ISetup<T> Setup(Expression<Action<TAnalog>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Action<T>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Action<T>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.Setup(this.mock, rewrittenExpression, condition);
			return new VoidSetupPhrase<T>(setup);
		}

		public ISetup<T, TResult> Setup<TResult>(Expression<Func<TAnalog, TResult>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TResult>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TResult>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.Setup(this.mock, rewrittenExpression, condition);
			return new NonVoidSetupPhrase<T, TResult>(setup);
		}

		public ISetupGetter<T, TProperty> SetupGet<TProperty>(Expression<Func<TAnalog, TProperty>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TProperty>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TProperty>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.SetupGet(this.mock, rewrittenExpression, condition);
			return new NonVoidSetupPhrase<T, TProperty>(setup);
		}

		public ISetupSetter<T, TProperty> SetupSet<TProperty>(Action<TAnalog> setterExpression)
		{
			throw new NotImplementedException();
		}

		public ISetup<T> SetupSet(Action<TAnalog> setterExpression)
		{
			throw new NotImplementedException();
		}

		private static LambdaExpression ReplaceDuck(LambdaExpression expression)
		{
			Debug.Assert(expression.Parameters.Count == 1);

			var targetParameter = Expression.Parameter(typeof(T), expression.Parameters[0].Name);
			return Expression.Lambda(DuckReplacerInstance.Visit(expression.Body), targetParameter);
		}


		private sealed class DuckReplacer : ExpressionVisitor
		{
			private Type duckType;
			private Type targetType;

			public DuckReplacer(Type duckType, Type targetType)
			{
				this.duckType = duckType;
				this.targetType = targetType;
			}

			protected override Expression VisitMethodCall(MethodCallExpression node)
			{
				if (node.Object is ParameterExpression left && left.Type == this.duckType)
				{
					var targetParameter = Expression.Parameter(this.targetType, left.Name);
					return Expression.Call(targetParameter, FindCorrespondingMethod(node.Method), node.Arguments);
				}
				else
				{
					return node;
				}
			}

			protected override Expression VisitMember(MemberExpression node)
			{
				if (node.Expression is ParameterExpression left && left.Type == this.duckType)
				{
					var targetParameter = Expression.Parameter(this.targetType, left.Name);
					return Expression.MakeMemberAccess(targetParameter, FindCorrespondingMember(node.Member));
				}
				else
				{
					return node;
				}
			}

			private MemberInfo FindCorrespondingMember(MemberInfo duckMember)
			{
				if (duckMember is MethodInfo duckMethod)
				{
					return FindCorrespondingMethod(duckMethod);
				}
				else if (duckMember is PropertyInfo duckProperty)
				{
					return FindCorrespondingProperty(duckProperty);
				}
				else
				{
					throw new NotSupportedException();
				}
			}

			private MethodInfo FindCorrespondingMethod(MethodInfo duckMethod)
			{
				var candidateTargetMethods =
					this.targetType
					.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
					.Where(ctm => IsCorrespondingMethod(duckMethod, ctm))
					.ToArray();

				if (candidateTargetMethods.Length == 0)
				{
					throw new ArgumentException(string.Format(Resources.ProtectedMemberNotFound, this.targetType, duckMethod));
				}

				Debug.Assert(candidateTargetMethods.Length == 1);

				var targetMethod = candidateTargetMethods[0];

				if (targetMethod.IsGenericMethodDefinition)
				{
					var duckGenericArgs = duckMethod.GetGenericArguments();
					targetMethod = targetMethod.MakeGenericMethod(duckGenericArgs);
				}

				return targetMethod;
			}

			private PropertyInfo FindCorrespondingProperty(PropertyInfo duckProperty)
			{
				var candidateTargetProperties =
					this.targetType
					.GetProperties(BindingFlags.NonPublic | BindingFlags.Instance)
					.Where(ctp => IsCorrespondingProperty(duckProperty, ctp))
					.ToArray();

				if (candidateTargetProperties.Length == 0)
				{
					throw new ArgumentException(string.Format(Resources.ProtectedMemberNotFound, this.targetType, duckProperty));
				}

				Debug.Assert(candidateTargetProperties.Length == 1);

				return candidateTargetProperties[0];
			}

			private static bool IsCorrespondingMethod(MethodInfo duckMethod, MethodInfo candidateTargetMethod)
			{
				if (candidateTargetMethod.Name != duckMethod.Name)
				{
					return false;
				}

				if (candidateTargetMethod.IsGenericMethod != duckMethod.IsGenericMethod)
				{
					return false;
				}

				if (candidateTargetMethod.IsGenericMethodDefinition)
				{
					// when both methods are generic, then the candidate method should be an open generic method
					// while the duck-type method should be a closed one. in this case, we close the former
					// over the same generic type arguments that the latter uses.

					Debug.Assert(!duckMethod.IsGenericMethodDefinition);

					var candidateGenericArgs = candidateTargetMethod.GetGenericArguments();
					var duckGenericArgs = duckMethod.GetGenericArguments();

					if (candidateGenericArgs.Length != duckGenericArgs.Length)
					{
						return false;
					}

					// this could perhaps go wrong due to generic type parameter constraints; if it does
					// go wrong, then obviously the duck-type method doesn't correspond to the candidate.
					try
					{
						candidateTargetMethod = candidateTargetMethod.MakeGenericMethod(duckGenericArgs);
					}
					catch
					{
						return false;
					}
				}

				var duckParameters = duckMethod.GetParameters();
				var candidateParameters = candidateTargetMethod.GetParameters();

				if (candidateParameters.Length != duckParameters.Length)
				{
					return false;
				}

				for (int i = 0, n = candidateParameters.Length; i < n; ++i)
				{
					if (candidateParameters[i].ParameterType != duckParameters[i].ParameterType)
					{
						return false;
					}
				}

				return true;
			}

			private static bool IsCorrespondingProperty(PropertyInfo duckProperty, PropertyInfo candidateTargetProperty)
			{
				return candidateTargetProperty.Name == duckProperty.Name
					&& candidateTargetProperty.PropertyType == duckProperty.PropertyType
					&& candidateTargetProperty.CanRead(out _) == duckProperty.CanRead(out _)
					&& candidateTargetProperty.CanWrite(out _) == duckProperty.CanWrite(out _);

				// TODO: parameter lists should be compared, too, to properly support indexers.
			}
		}

	}
}
